package dnstt_client

import (
	"errors"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// resolverState tracks liveness statistics for a single UDP resolver.
// All fields are safe for concurrent access.
type resolverState struct {
	addr             *net.UDPAddr
	consecutiveFails atomic.Int32
	backoffUntil     atomic.Int64 // unix nanosecond deadline; 0 = no backoff
}

func (r *resolverState) isHealthy() bool {
	bu := r.backoffUntil.Load()
	return bu == 0 || time.Now().UnixNano() >= bu
}

func (r *resolverState) recordSuccess() {
	r.consecutiveFails.Store(0)
	r.backoffUntil.Store(0)
}

func (r *resolverState) recordFailure() {
	n := r.consecutiveFails.Add(1)
	// Exponential backoff: 2^n seconds, capped at 30 s.
	backoffSec := int64(1) << uint(n)
	if backoffSec > 30 {
		backoffSec = 30
	}
	deadline := time.Now().Add(time.Duration(backoffSec) * time.Second).UnixNano()
	r.backoffUntil.Store(deadline)
}

// UDPQueryPacketConn sends each DNS query on a fresh UDP socket (random
// source port) to avoid middlebox 4-tuple blocking. It supports multiple
// resolvers with automatic health-based failover.
//
// It exposes LargestResponse() for adaptive EDNS0 probing: the caller
// (DNSPacketConn) can read the maximum response size observed so far and
// decide when to advertise a larger EDNS0 payload size.
type UDPQueryPacketConn struct {
	*turbotunnel.QueuePacketConn

	states  []*resolverState
	timeout time.Duration

	closed chan struct{}
	once   sync.Once

	// largestResponse is the largest raw DNS response observed (bytes).
	largestResponse atomic.Int32
}

// UDPQueryPacketConnConfig holds optional configuration for NewUDPQueryPacketConn.
type UDPQueryPacketConnConfig struct {
	// Timeout is the per-query read deadline on the UDP socket. Default 3s.
	Timeout time.Duration
}

// NewUDPQueryPacketConn creates a UDPQueryPacketConn backed by the given
// resolver list. numSenders controls the concurrency (default 24).
func NewUDPQueryPacketConn(resolvers []*net.UDPAddr, numSenders int, config *UDPQueryPacketConnConfig) (*UDPQueryPacketConn, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("no UDP resolvers provided")
	}
	if numSenders <= 0 {
		numSenders = 24
	}
	timeout := 3 * time.Second
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}

	states := make([]*resolverState, len(resolvers))
	for i, addr := range resolvers {
		states[i] = &resolverState{addr: addr}
	}

	c := &UDPQueryPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
		states:          states,
		timeout:         timeout,
		closed:          make(chan struct{}),
	}

	for i := 0; i < numSenders; i++ {
		go c.sendLoop()
	}
	return c, nil
}

// LargestResponse returns the size (bytes) of the largest DNS response
// received so far. DNSPacketConn uses this to decide whether to promote
// the advertised EDNS0 payload size.
func (c *UDPQueryPacketConn) LargestResponse() int {
	return int(c.largestResponse.Load())
}

// pickResolver returns the best healthy resolver using random selection.
// If all resolvers are in backoff, it resets all of them and picks randomly.
func (c *UDPQueryPacketConn) pickResolver() *resolverState {
	healthy := make([]*resolverState, 0, len(c.states))
	for _, s := range c.states {
		if s.isHealthy() {
			healthy = append(healthy, s)
		}
	}
	if len(healthy) == 0 {
		// All resolvers are in backoff — reset and continue.
		for _, s := range c.states {
			s.backoffUntil.Store(0)
			s.consecutiveFails.Store(0)
		}
		return c.states[rand.IntN(len(c.states))]
	}
	return healthy[rand.IntN(len(healthy))]
}

func (c *UDPQueryPacketConn) sendLoop() {
	out := c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{})
	var buf [8192]byte

	for {
		select {
		case <-c.closed:
			return
		case p, ok := <-out:
			if !ok {
				return
			}

			state := c.pickResolver()

			// Fresh socket per query => random ephemeral source port, defeating
			// 4-tuple-based blocking by DPI middleboxes.
			uc, err := net.ListenUDP("udp", nil)
			if err != nil {
				log.Printf("udp: ListenUDP: %v", err)
				state.recordFailure()
				continue
			}

			_ = uc.SetDeadline(time.Now().Add(c.timeout))
			if _, err = uc.WriteToUDP(p, state.addr); err != nil {
				_ = uc.Close()
				state.recordFailure()
				continue
			}

			n, _, err := uc.ReadFromUDP(buf[:])
			_ = uc.Close()

			if err != nil {
				// Timeout or packet loss — KCP handles retransmission.
				state.recordFailure()
				continue
			}

			state.recordSuccess()

			// Track largest response for EDNS0 probing.
			if int32(n) > c.largestResponse.Load() {
				c.largestResponse.Store(int32(n))
			}

			c.QueuePacketConn.QueueIncoming(buf[:n], turbotunnel.DummyAddr{})
		}
	}
}

func (c *UDPQueryPacketConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		err = c.QueuePacketConn.Close()
	})
	return err
}
