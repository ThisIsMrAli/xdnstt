package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"

	dc "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func main() {
	var (
		listenAddr   string
		udpResolvers string
		domainStr    string
		domainsStr   string
		pubkeyHex    string

		edns0         int
		probeEDNS0    bool
		cover         bool
		udpSenders    int
		udpTimeoutMS  int
		jitter        bool
		burst         bool
		initPollMS    int
		maxPollMS     int
		metricsEveryS int
	)

	flag.StringVar(&listenAddr, "listen", "127.0.0.1:1080", "local TCP listen address (clients connect here; speak SOCKS5/HTTP CONNECT/etc, bytes are tunneled)")
	flag.StringVar(&udpResolvers, "udp", "", "comma-separated UDP resolvers host:port (e.g. 1.1.1.1:53,8.8.8.8:53)")
	flag.StringVar(&domainStr, "domain", "", "tunnel domain (e.g. t.example.com)")
	flag.StringVar(&domainsStr, "domains", "", "comma-separated domain list (random per session); overrides -domain when set")
	flag.StringVar(&pubkeyHex, "pubkey", "", "server public key hex (64 hex digits)")

	flag.IntVar(&edns0, "edns0", 512, "starting EDNS0 UDP payload size to advertise (UDP default 512; probing promotes automatically)")
	flag.BoolVar(&probeEDNS0, "probeedns0", true, "enable automatic EDNS0 probing (promotes to 1232/4096 when path supports it)")
	flag.BoolVar(&cover, "cover", true, "mix A/AAAA cover queries into idle polls (breaks 100% TXT fingerprint)")
	flag.IntVar(&udpSenders, "udpsenders", 6, "concurrent per-query UDP sender goroutines (default 6)")
	flag.IntVar(&udpTimeoutMS, "udptimeoutms", 3000, "per-query UDP response deadline in milliseconds (default 3000)")
	flag.BoolVar(&jitter, "jitter", true, "enable poll timer jitter (default true)")
	flag.BoolVar(&burst, "burst", true, "enable burst-mode idle polling (default true; requires -jitter=true)")
	flag.IntVar(&initPollMS, "initpollms", 500, "initial poll delay in milliseconds (UDP default 500)")
	flag.IntVar(&maxPollMS, "maxpollms", 5000, "max poll delay in milliseconds (UDP default 5000)")
	flag.IntVar(&metricsEveryS, "metricsevery", 60, "log metrics every N seconds (0 disables)")

	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if udpResolvers == "" {
		fatalf("missing -udp (resolver list)")
	}
	if pubkeyHex == "" {
		fatalf("missing -pubkey")
	}
	if domainsStr == "" && domainStr == "" {
		fatalf("missing -domain (or -domains)")
	}

	pubkey, err := noise.DecodeKey(pubkeyHex)
	if err != nil {
		fatalf("invalid -pubkey: %v", err)
	}

	var domains []string
	if domainsStr != "" {
		for _, p := range strings.Split(domainsStr, ",") {
			if p = strings.TrimSpace(p); p != "" {
				domains = append(domains, p)
			}
		}
	} else {
		domains = []string{domainStr}
	}
	if len(domains) == 0 {
		fatalf("domains list is empty")
	}

	resolvers, err := parseUDPResolvers(udpResolvers)
	if err != nil {
		fatalf("invalid -udp: %v", err)
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fatalf("listen %s: %v", listenAddr, err)
	}
	defer ln.Close()
	log.Printf("listening on %s", listenAddr)

	// Manage a shared smux session; reconnect when it dies.
	var (
		sessMu sync.Mutex
		sess   *smux.Session
		kconn  *kcp.UDPSession
		pconn  net.PacketConn
		done   = make(chan struct{})
	)

	ensureSession := func() (*smux.Session, error) {
		sessMu.Lock()
		defer sessMu.Unlock()
		if sess != nil && !sess.IsClosed() {
			return sess, nil
		}
		// Close any leftovers.
		if sess != nil {
			_ = sess.Close()
		}
		if kconn != nil {
			_ = kconn.Close()
		}
		if pconn != nil {
			_ = pconn.Close()
		}

		chosen := domains[int(time.Now().UnixNano())%len(domains)]
		domain, err := dns.ParseName(chosen)
		if err != nil {
			return nil, fmt.Errorf("invalid domain %q: %w", chosen, err)
		}
		// Compute effective query MTU from domain length. This is critical:
		// if KCP MTU is too large, DNSPacketConn.send will reject packets as
		// "too long" or produce names >255 octets.
		mtu := dnsNameCapacity(domain) - 8 - 1 - dc.NumPadding - 1
		if mtu < 80 {
			return nil, fmt.Errorf("domain %s leaves only %d bytes for payload; use a shorter tunnel domain", domain, mtu)
		}
		// DNSPacketConn can only encode <224 bytes per query.
		if mtu > 223 {
			mtu = 223
		}

		// UDP transport: per-query socket, health-tracked resolvers.
		remoteAddr := turbotunnel.DummyAddr{}
		timeout := 3 * time.Second
		if udpTimeoutMS > 0 {
			timeout = time.Duration(udpTimeoutMS) * time.Millisecond
		}
		upc, err := dc.NewUDPQueryPacketConn(resolvers, udpSenders, &dc.UDPQueryPacketConnConfig{Timeout: timeout})
		if err != nil {
			return nil, err
		}

		dnsCfg := &dc.DNSPacketConnConfig{
			InitPollDelay: time.Duration(initPollMS) * time.Millisecond,
			MaxPollDelay:  time.Duration(maxPollMS) * time.Millisecond,
			EDNS0Size:     edns0,
			ProbeEDNS0:    probeEDNS0,
			CoverQueries:  cover,
			PollJitter:    jitter,
			BurstMode:     burst && jitter,
		}
		pconn = dc.NewDNSPacketConnWithConfig(upc, remoteAddr, domain, dnsCfg)

		// KCP on top.
		kconn, err = kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
		if err != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("kcp: %w", err)
		}
		kconn.SetStreamMode(true)
		kconn.SetNoDelay(1, 20, 2, 1)
		kconn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		if rc := kconn.SetMtu(mtu); !rc {
			return nil, fmt.Errorf("kcp SetMtu(%d) failed", mtu)
		}

		// Noise.
		rw, err := noise.NewClient(kconn, pubkey)
		if err != nil {
			_ = kconn.Close()
			_ = pconn.Close()
			return nil, fmt.Errorf("noise: %w", err)
		}

		// smux session.
		smuxConfig := smux.DefaultConfig()
		smuxConfig.Version = 2
		smuxConfig.KeepAliveTimeout = 2 * time.Minute
		smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
		sess, err = smux.Client(rw, smuxConfig)
		if err != nil {
			_ = kconn.Close()
			_ = pconn.Close()
			return nil, fmt.Errorf("smux: %w", err)
		}

		log.Printf("session established (domain=%s)", chosen)
		return sess, nil
	}

	if metricsEveryS > 0 {
		dc.StartMetricsLogger(time.Duration(metricsEveryS)*time.Second, done)
	}

	// Shutdown on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(done)
		_ = ln.Close()
		sessMu.Lock()
		defer sessMu.Unlock()
		if sess != nil {
			_ = sess.Close()
		}
		if kconn != nil {
			_ = kconn.Close()
		}
		if pconn != nil {
			_ = pconn.Close()
		}
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
			}
			log.Printf("accept: %v", err)
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()

			s, err := ensureSession()
			if err != nil {
				log.Printf("session: %v", err)
				return
			}

			st, err := s.OpenStream()
			if err != nil {
				// Force reconnect once and retry.
				sessMu.Lock()
				if sess != nil {
					_ = sess.Close()
				}
				sess = nil
				sessMu.Unlock()

				s, err = ensureSession()
				if err != nil {
					log.Printf("session(retry): %v", err)
					return
				}
				st, err = s.OpenStream()
				if err != nil {
					log.Printf("open stream: %v", err)
					return
				}
			}
			defer st.Close()

			// Raw byte tunnel. Whatever the local client speaks (SOCKS5, HTTP CONNECT),
			// will be spoken to the upstream on the server (typically Dante SOCKS).
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = io.Copy(st, conn); _ = st.Close() }()
			go func() { defer wg.Done(); _, _ = io.Copy(conn, st); _ = conn.Close() }()
			wg.Wait()
		}(c)
	}
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name. Mirrors the logic in dnstt-client/lib.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	capacity := 255
	// Null terminator.
	capacity -= 1
	for _, label := range domain {
		// Label and length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

func parseUDPResolvers(spec string) ([]*net.UDPAddr, error) {
	var resolvers []*net.UDPAddr
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ra, err := net.ResolveUDPAddr("udp", part)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, ra)
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("empty resolver list")
	}
	return resolvers, nil
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

