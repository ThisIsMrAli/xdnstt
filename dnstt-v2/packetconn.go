package dnsttv2

import (
	"net"
	"sync"
	"time"
)

// PacketConn wraps an underlying net.PacketConn and transparently applies
// v2 FEC wrapping/unwrapping to the datagrams. It is intended to sit directly
// under KCP (KCP sees the original datagrams; DNS carries v2 packets).
type PacketConn struct {
	under net.PacketConn
	peer  net.Addr

	enc *FECEncoder
	dec *FECDecoder

	mu     sync.Mutex
	recvQ  [][]byte
	closed bool
}

func NewPacketConn(under net.PacketConn, peer net.Addr, connID uint32, fecGroupSize int) *PacketConn {
	return &PacketConn{
		under: under,
		peer:  peer,
		enc:   NewFECEncoder(connID, fecGroupSize),
		dec:   NewFECDecoder(connID),
	}
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.mu.Lock()
	if len(c.recvQ) > 0 {
		msg := c.recvQ[0]
		c.recvQ = c.recvQ[1:]
		c.mu.Unlock()

		n = copy(p, msg)
		return n, c.peer, nil
	}
	c.mu.Unlock()

	var buf [4096]byte
	for {
		n0, a0, err0 := c.under.ReadFrom(buf[:])
		if err0 != nil {
			return 0, nil, err0
		}
		_ = a0

		inners := c.dec.ConsumeV2Packet(buf[:n0])
		if len(inners) == 0 {
			continue
		}

		c.mu.Lock()
		for _, in := range inners[1:] {
			c.recvQ = append(c.recvQ, in)
		}
		first := inners[0]
		c.mu.Unlock()

		n = copy(p, first)
		return n, c.peer, nil
	}
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	_ = addr
	dataPkt, fecPkt := c.enc.WrapData(p)
	if _, err = c.under.WriteTo(dataPkt, c.peer); err != nil {
		return 0, err
	}
	if fecPkt != nil {
		if _, err = c.under.WriteTo(fecPkt, c.peer); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *PacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.under.Close()
}

func (c *PacketConn) LocalAddr() net.Addr  { return c.under.LocalAddr() }
func (c *PacketConn) SetDeadline(t time.Time) error {
	return c.under.SetDeadline(t)
}
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	return c.under.SetReadDeadline(t)
}
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	return c.under.SetWriteDeadline(t)
}

