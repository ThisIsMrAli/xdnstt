package dnsttv2

import (
	"encoding/binary"
	"errors"
)

// v2 packet wire format (inside the existing DNS "packet" container):
//
//   0..2   magic "DN2"
//   3      version (currently 1)
//   4      type
//   5      flags
//   6..9   connID (uint32)
//   10..13 seq (uint32)  // packet sequence number
//   14..17 ack (uint32)  // cumulative ack
//   18..21 ackBits (uint32) // selective ack bitmap for the previous 32 packets
//   22..   payload (type-dependent)
//
// This header is intentionally compact so it fits well under tiny DNS limits.

const (
	magic0 = 'D'
	magic1 = 'N'
	magic2 = '2'

	Version1 = 1

	HeaderLen = 22
)

type PacketType uint8

const (
	TypeHello PacketType = 0x01 // v2 mode marker + parameters
	TypeData  PacketType = 0x02 // carries one or more framed stream chunks
	TypeFEC   PacketType = 0x03 // XOR parity for a small block (optional)
	TypeClose PacketType = 0x04 // graceful close
)

var (
	ErrTooShort = errors.New("dnstt-v2: packet too short")
	ErrBadMagic = errors.New("dnstt-v2: bad magic")
	ErrBadVer   = errors.New("dnstt-v2: unsupported version")
)

type Header struct {
	Type    PacketType
	Flags   uint8
	ConnID  uint32
	Seq     uint32
	Ack     uint32
	AckBits uint32
}

func IsV2Packet(p []byte) bool {
	return len(p) >= HeaderLen && p[0] == magic0 && p[1] == magic1 && p[2] == magic2 && p[3] == Version1
}

func ParseHeader(p []byte) (Header, []byte, error) {
	if len(p) < HeaderLen {
		return Header{}, nil, ErrTooShort
	}
	if p[0] != magic0 || p[1] != magic1 || p[2] != magic2 {
		return Header{}, nil, ErrBadMagic
	}
	if p[3] != Version1 {
		return Header{}, nil, ErrBadVer
	}
	h := Header{
		Type:    PacketType(p[4]),
		Flags:   p[5],
		ConnID:  binary.BigEndian.Uint32(p[6:10]),
		Seq:     binary.BigEndian.Uint32(p[10:14]),
		Ack:     binary.BigEndian.Uint32(p[14:18]),
		AckBits: binary.BigEndian.Uint32(p[18:22]),
	}
	return h, p[HeaderLen:], nil
}

func AppendHeader(dst []byte, h Header) []byte {
	var b [HeaderLen]byte
	b[0] = magic0
	b[1] = magic1
	b[2] = magic2
	b[3] = Version1
	b[4] = byte(h.Type)
	b[5] = h.Flags
	binary.BigEndian.PutUint32(b[6:10], h.ConnID)
	binary.BigEndian.PutUint32(b[10:14], h.Seq)
	binary.BigEndian.PutUint32(b[14:18], h.Ack)
	binary.BigEndian.PutUint32(b[18:22], h.AckBits)
	return append(dst, b[:]...)
}

