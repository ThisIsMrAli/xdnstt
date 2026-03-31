// Package lib provides the core dnstt server logic with pluggable hooks
// for payload decoding and response handling. External modules can override
// the default base32 decoding by supplying custom hooks.
package lib

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	dnsttv2 "www.bamsoftware.com/git/dnstt.git/dnstt-v2"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// smux streams will be closed after this much time without receiving data.
	IdleTimeout = 2 * time.Minute

	// ResponseTTL is the base TTL for DNS answer resource records.
	// The actual TTL per response is randomized ±20% around this value so
	// that DPI systems cannot fingerprint a fixed TTL pattern.
	ResponseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	MaxResponseDelay = 1 * time.Second

	// How long to wait for a TCP connection to upstream to be established.
	UpstreamDialTimeout = 30 * time.Second

	// Maximum concurrent streams per KCP session. Prevents a single client
	// from exhausting server resources.
	MaxStreamsPerSession = 32

	// Maximum concurrent KCP sessions. Each session consumes ~1MB+ of memory
	// (KCP buffers + smux + Noise state). Limits total memory usage on
	// high-traffic public servers.
	MaxSessions = 512
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// isShutdownError reports whether err is an expected error produced when the
// server is shutting down gracefully (closed connections/pipes). These are
// suppressed from logs to keep shutdown output clean.
func isShutdownError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed") ||
		strings.Contains(s, "closed network connection") ||
		strings.Contains(s, "closed pipe") ||
		strings.Contains(s, "io: read/write on closed pipe")
}

// randomTTL returns a TTL ±20% around ResponseTTL to prevent fingerprinting
// on fixed TTL values.
func randomTTL() uint32 {
	// Variation is ±12 seconds (20% of 60).
	const variation = ResponseTTL / 5
	return ResponseTTL - variation + uint32(rand.IntN(2*variation+1))
}

// serverMetrics counts key server-side events for periodic logging.
type serverMetrics struct {
	queriesRecv  atomic.Uint64
	queriesSent  atomic.Uint64
	bytesRecv    atomic.Uint64
	bytesSent    atomic.Uint64
	activeSess   atomic.Int64
	activeStream atomic.Int64
}

// DecodeFunc decodes subdomain prefix labels into a binary payload.
// It receives the labels that precede the tunnel domain.
type DecodeFunc func(prefix dns.Name) ([]byte, error)

// NonTXTResponseFunc builds response data for non-TXT query types (e.g. A, AAAA).
// Returns the RR data bytes, or nil if the query type is not handled.
type NonTXTResponseFunc func(qtype uint16) []byte

// ServerHooks allows external modules to plug custom decoding and response
// behavior into the dnstt server. This follows the same pattern as
// DNSPacketConnHooks in dnstt-client/lib.
type ServerHooks struct {
	// DecodePayload, if non-nil, replaces the default base32 decoder.
	DecodePayload DecodeFunc

	// AcceptQueryType, if non-nil, determines which query types are
	// processed. The default accepts only TXT.
	AcceptQueryType func(qtype uint16) bool

	// HandleNonTXT, if non-nil, is called for accepted non-TXT queries
	// to produce a response. The default behavior is NXDOMAIN for non-TXT.
	HandleNonTXT NonTXTResponseFunc
}

// defaultDecode is the standard base32 decoder used by upstream dnstt.
func defaultDecode(prefix dns.Name) ([]byte, error) {
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		return nil, err
	}
	return payload[:n], nil
}

// defaultAcceptQueryType accepts TXT queries only.
func defaultAcceptQueryType(qtype uint16) bool {
	return qtype == dns.RRTypeTXT
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
	// PayloadLimit is the maximum UDP payload size indicated by the requester
	// (EDNS0 UDP payload size), clamped to the server's configured max.
	PayloadLimit int
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(ioutil.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
func responseFor(query *dns.Message, domain dns.Name, maxUDPPayload int, hooks *ServerHooks) (*dns.Message, []byte, int) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		return nil, nil, 0
	}

	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil, 0
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil, 0
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}

	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil, 0
	}
	question := query.Question[0]
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s", question.Name)
		return resp, nil, 0
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil, 0
	}

	acceptQtype := defaultAcceptQueryType
	if hooks != nil && hooks.AcceptQueryType != nil {
		acceptQtype = hooks.AcceptQueryType
	}
	if !acceptQtype(question.Type) {
		resp.Flags |= dns.RcodeNameError
		return resp, nil, 0
	}

	decode := defaultDecode
	if hooks != nil && hooks.DecodePayload != nil {
		decode = hooks.DecodePayload
	}
	payload, err := decode(prefix)
	if err != nil {
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: decoding: %v", err)
		return resp, nil, 0
	}

	// Dynamic payload limit: clamp to both the requester's advertised limit and
	// the server's configured maximum. This avoids FORMERR when the path only
	// supports 512-byte UDP responses (common in censored networks).
	limit := payloadSize
	if maxUDPPayload > 0 && limit > maxUDPPayload {
		limit = maxUDPPayload
	}
	return resp, payload, limit
}

// handleStream bidirectionally connects a client stream with a TCP socket.
func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{
		Timeout: UpstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer func() {
		_ = upstreamConn.Close()
	}()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, upstreamTCPConn)
		_ = upstreamTCPConn.CloseRead()
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		_ = upstreamTCPConn.CloseWrite()
		if err != nil {
			// Stream was forcefully closed (e.g. session timeout after
			// client disconnect). Close the upstream read side so the
			// upstream→stream goroutine unblocks instead of leaking.
			_ = upstreamTCPConn.CloseRead()
		}
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session.
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string) error {
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // 1MB — supports ~10 Mbps at 100ms RTT
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer func() {
		_ = sess.Close()
	}()

	streamSem := make(chan struct{}, MaxStreamsPerSession)

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}

		select {
		case streamSem <- struct{}{}:
		default:
			// At capacity — reject this stream.
			log.Printf("session %08x: rejecting stream %d (limit %d)", conn.GetConv(), stream.ID(), MaxStreamsPerSession)
			_ = stream.Close()
			continue
		}

		go func() {
			defer func() {
				_ = stream.Close()
				<-streamSem
			}()
			err := handleStream(stream, upstream, conn.GetConv())
			if err != nil {
				log.Printf("session %08x: stream %d error: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string, clientPayloadLimit *sync.Map) error {
	sessionSem := make(chan struct{}, MaxSessions)

	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}

		select {
		case sessionSem <- struct{}{}:
		default:
			// At capacity — reject this session.
			log.Printf("rejecting session %08x (limit %d)", conn.GetConv(), MaxSessions)
			_ = conn.Close()
			continue
		}

		conn.SetStreamMode(true)
		// Fast mode: no-delay ACK, 20 ms flush interval, fast-resend after
		// 2 ACK gaps. This mirrors the client-side KCP settings so both ends
		// retransmit aggressively on a lossy path, improving throughput under
		// the high packet-loss conditions common in censored UDP paths.
		conn.SetNoDelay(1, 20, 2, 1)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)

		// Default MTU is based on the server's configured max UDP payload,
		// but for many networks (and censored environments) the effective
		// downstream response size is 512. If we keep a large KCP MTU while
		// DNS responses are limited to 512, downstream packets will be
		// truncated and performance collapses. Clamp MTU per client using
		// the most recently observed EDNS0 payload limit.
		effectiveMTU := mtu
		if clientPayloadLimit != nil {
			if cid, ok := conn.RemoteAddr().(turbotunnel.ClientID); ok {
				if v, ok := clientPayloadLimit.Load(cid.String()); ok {
					if limit, ok := v.(int); ok && limit >= 512 {
						mep := ComputeMaxEncodedPayload(limit)
						if m := mep - 2; m >= 80 && m < effectiveMTU {
							effectiveMTU = m
						}
					}
				}
			}
		}

		if rc := conn.SetMtu(effectiveMTU); !rc {
			panic(rc)
		}
		go func() {
			defer func() {
				_ = conn.Close()
				<-sessionSem
			}()
			err := acceptStreams(conn, privkey, upstream)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x: %v", conn.GetConv(), err)
			}
		}()
	}
}

// recvLoop extracts packets from incoming DNS queries.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, maxUDPPayload int, hooks *ServerHooks, clientPayloadLimit *sync.Map, clientMode *sync.Map, v2Dec *sync.Map) error {

	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("cannot parse DNS query: %v", err)
			continue
		}

		resp, payload, limit := responseFor(&query, domain, maxUDPPayload, hooks)
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if clientPayloadLimit != nil && limit >= 512 {
			clientPayloadLimit.Store(clientID.String(), limit)
		}
		if n == len(clientID) {
			modeAny, _ := clientMode.Load(clientID.String())
			mode, _ := modeAny.(string)
			// Default until proven otherwise.
			if mode == "" {
				mode = "v1"
			}

			r := bytes.NewReader(payload)
			for {
				p, err := nextPacket(r)
				if err != nil {
					break
				}
				// If we haven't classified this client yet, look for a v2 packet marker.
				if mode == "v1" && dnsttv2.IsV2Packet(p) {
					mode = "v2"
					clientMode.Store(clientID.String(), "v2")
				}
				if mode == "v2" {
					// v2 packets carry KCP datagrams inside their payload (with optional XOR-FEC).
					v, _ := v2Dec.LoadOrStore(clientID.String(), dnsttv2.NewFECDecoder(binary.BigEndian.Uint32(clientID[0:4])))
					dec := v.(*dnsttv2.FECDecoder)
					for _, inner := range dec.ConsumeV2Packet(p) {
						ttConn.QueueIncoming(inner, clientID)
					}
				} else {
					ttConn.QueueIncoming(p, clientID)
				}
			}
		} else {
			if resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
			}
		}
		if resp != nil {
			select {
			case ch <- &record{Resp: resp, Addr: addr, ClientID: clientID, PayloadLimit: limit}:
			default:
			}
		}
	}
}

// sendLoop sends DNS responses, packing downstream data into TXT or A answers.

func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, maxEncodedPayload int, maxUDPPayload int, hooks *ServerHooks, clientMode *sync.Map, v2Enc *sync.Map) error {
	// Cache ComputeMaxEncodedPayload(limit) per payload limit.
	type cached struct {
		maxEncoded int
	}
	var cache sync.Map // map[int]cached

	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			qtype := rec.Resp.Question[0].Type

			// Check if a hook wants to handle non-tunnel responses.
			if qtype != dns.RRTypeTXT && qtype != dns.RRTypeA && qtype != dns.RRTypeAAAA && hooks != nil && hooks.HandleNonTXT != nil {
				if data := hooks.HandleNonTXT(qtype); data != nil {
					rec.Resp.Answer = []dns.RR{
						{
							Name:  rec.Resp.Question[0].Name,
							Type:  qtype,
							Class: rec.Resp.Question[0].Class,
							TTL:   randomTTL(), // randomized to break DPI TTL fingerprint
							Data:  data,
						},
					}
					goto send
				}
			}

			if qtype == dns.RRTypeTXT {
				// Per-request payload limit (EDNS0 size clamped to server max).
				limit := rec.PayloadLimit
				if limit <= 0 {
					limit = maxUDPPayload
				}
				// Compute max encoded payload for this limit (memoized).
				mep := maxEncodedPayload
				if v, ok := cache.Load(limit); ok {
					mep = v.(cached).maxEncoded
				} else {
					mep = ComputeMaxEncodedPayload(limit)
					cache.Store(limit, cached{maxEncoded: mep})
				}

				// Collect downstream packets.
				var payload bytes.Buffer
				remaining := mep
				timer := time.NewTimer(MaxResponseDelay)
				for {
					var p []byte
					unstash := ttConn.Unstash(rec.ClientID)
					outgoing := ttConn.OutgoingQueue(rec.ClientID)
					select {
					case p = <-unstash:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						default:
							select {
							case p = <-unstash:
							case p = <-outgoing:
							case <-timer.C:
							case nextRec = <-ch:
							}
						}
					}
					timer.Reset(0)

					if len(p) == 0 {
						break
					}

					remaining -= 2 + len(p)
					if payload.Len() == 0 {
						// Allow first packet even if oversized.
					} else if remaining < 0 {
						ttConn.Stash(p, rec.ClientID)
						break
					}
					if int(uint16(len(p))) != len(p) {
						panic(len(p))
					}
					// For v2 clients, wrap outgoing KCP datagrams into v2 packets (and
					// occasionally append XOR-FEC parity packets) before embedding into
					// the DNS response payload.
					modeAny, _ := clientMode.Load(rec.ClientID.String())
					mode, _ := modeAny.(string)
					if mode == "v2" {
						v, _ := v2Enc.LoadOrStore(rec.ClientID.String(), dnsttv2.NewFECEncoder(binary.BigEndian.Uint32(rec.ClientID[0:4]), 6))
						enc := v.(*dnsttv2.FECEncoder)
						dataPkt, fecPkt := enc.WrapData(p)
						_ = binary.Write(&payload, binary.BigEndian, uint16(len(dataPkt)))
						payload.Write(dataPkt)
						if fecPkt != nil {
							_ = binary.Write(&payload, binary.BigEndian, uint16(len(fecPkt)))
							payload.Write(fecPkt)
						}
					} else {
						_ = binary.Write(&payload, binary.BigEndian, uint16(len(p)))
						payload.Write(p)
					}
				}
				timer.Stop()

			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  dns.RRTypeTXT,
					Class: rec.Resp.Question[0].Class,
					TTL:   randomTTL(), // randomized to break DPI TTL fingerprint
					Data:  dns.EncodeRDataTXT(payload.Bytes()),
				},
			}
			}
		}

	send:
		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		payloadLimit := rec.PayloadLimit
		if payloadLimit <= 0 {
			payloadLimit = maxUDPPayload
		}
		if payloadLimit > 0 && len(buf) > payloadLimit {
			log.Printf("truncating response of %d bytes to max of %d", len(buf), payloadLimit)
			buf = buf[:payloadLimit]
			buf[2] |= 0x02 // TC = 1
		}

		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("WriteTo temporary error: %v", err)
				continue
			}
			return err
		}
	}
	return nil
}

// ComputeMaxEncodedPayload computes the maximum amount of downstream TXT RR
// data that keeps the overall response size under the given limit.
func ComputeMaxEncodedPayload(limit int) int {
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  dns.RRTypeTXT,
				Class: dns.RRTypeTXT,
			},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
	resp, _, _ := responseFor(query, [][]byte{}, limit, nil)
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   ResponseTTL,
			Data:  nil,
		},
	}

	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

// Run starts the dnstt server with the given configuration and optional hooks.
// If hooks is nil, the server behaves identically to upstream dnstt (base32, TXT-only).
func Run(privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, maxUDPPayload int, hooks *ServerHooks) error {
	defer func() {
		_ = dnsConn.Close()
	}()

	log.Printf("pubkey %x", noise.PubkeyFromPrivkey(privkey))

	maxEncodedPayload := ComputeMaxEncodedPayload(maxUDPPayload)
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Tracks the most recent EDNS0 UDP payload limit seen per client ID,
	// to clamp KCP MTU per client for 512-limited paths.
	var clientPayloadLimit sync.Map // map[string]int
	// Tracks whether a client speaks v1 or v2.
	var clientMode sync.Map // map[string]string
	// v2 encoder/decoder state per client.
	var v2Enc sync.Map // map[string]*dnsttv2.FECEncoder
	var v2Dec sync.Map // map[string]*dnsttv2.FECDecoder

	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, IdleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer func() {
		_ = ln.Close()
	}()
	go func() {
		err := acceptSessions(ln, privkey, mtu, upstream, &clientPayloadLimit)
		if err != nil {
			// "io: read/write on closed pipe" is expected on graceful shutdown
			// when the KCP listener is closed. Suppress it.
			if !isShutdownError(err) {
				log.Printf("acceptSessions: %v", err)
			}
		}
	}()

	ch := make(chan *record, 100)
	defer close(ch)

	go func() {
		err := sendLoop(dnsConn, ttConn, ch, maxEncodedPayload, maxUDPPayload, hooks, &clientMode, &v2Enc)
		if err != nil {
			if !isShutdownError(err) {
				log.Printf("sendLoop: %v", err)
			}
		}
	}()

	return recvLoop(domain, dnsConn, ttConn, ch, maxUDPPayload, hooks, &clientPayloadLimit, &clientMode, &v2Dec)
}
