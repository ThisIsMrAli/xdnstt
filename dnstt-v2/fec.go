package dnsttv2

import (
	"encoding/binary"
	"sync"
)

// FECEncoder implements a simple XOR parity scheme over v2 data packets.
// It does not replace end-to-end reliability (KCP still provides that);
// it aims to reduce effective loss on highly lossy DNS paths.
type FECEncoder struct {
	mu        sync.Mutex
	connID    uint32
	nextSeq   uint32
	groupSize int

	pendSeq  []uint32
	pendData [][]byte // inner payload bytes (opaque to v2)
}

func NewFECEncoder(connID uint32, groupSize int) *FECEncoder {
	if groupSize <= 1 {
		groupSize = 6
	}
	return &FECEncoder{
		connID:    connID,
		nextSeq:   1,
		groupSize: groupSize,
		pendSeq:   make([]uint32, 0, groupSize),
		pendData:  make([][]byte, 0, groupSize),
	}
}

// WrapData returns a v2 TypeData packet carrying the given inner payload.
// It may also return a TypeFEC parity packet when a group completes.
func (e *FECEncoder) WrapData(inner []byte) (dataPkt []byte, fecPkt []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()

	seq := e.nextSeq
	e.nextSeq++

	dataPkt = AppendHeader(nil, Header{
		Type:   TypeData,
		ConnID: e.connID,
		Seq:    seq,
	})
	dataPkt = append(dataPkt, inner...)

	e.pendSeq = append(e.pendSeq, seq)
	e.pendData = append(e.pendData, append([]byte(nil), inner...))

	if len(e.pendData) < e.groupSize {
		return dataPkt, nil
	}

	// Build XOR parity for exactly one-loss recovery in this group.
	baseSeq := e.pendSeq[0]
	count := len(e.pendData)
	maxLen := 0
	for _, d := range e.pendData {
		if len(d) > maxLen {
			maxLen = len(d)
		}
	}

	// Parity payload layout:
	// baseSeq (u32) | count (u8) | maxLen (u16) | lens[count] (u16 each) | xor[maxLen]
	var payload []byte
	var tmp [7]byte
	binary.BigEndian.PutUint32(tmp[0:4], baseSeq)
	tmp[4] = uint8(count)
	binary.BigEndian.PutUint16(tmp[5:7], uint16(maxLen))
	payload = append(payload, tmp[:]...)

	for i := 0; i < count; i++ {
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(e.pendData[i])))
		payload = append(payload, lb[:]...)
	}

	xor := make([]byte, maxLen)
	for _, d := range e.pendData {
		for i := 0; i < maxLen; i++ {
			var b byte
			if i < len(d) {
				b = d[i]
			}
			xor[i] ^= b
		}
	}
	payload = append(payload, xor...)

	fecSeq := e.nextSeq
	e.nextSeq++
	fecPkt = AppendHeader(nil, Header{
		Type:   TypeFEC,
		ConnID: e.connID,
		Seq:    fecSeq,
	})
	fecPkt = append(fecPkt, payload...)

	// Reset pending group.
	e.pendSeq = e.pendSeq[:0]
	e.pendData = e.pendData[:0]

	return dataPkt, fecPkt
}

type FECDecoder struct {
	mu     sync.Mutex
	connID uint32

	// data maps v2 sequence number -> inner payload.
	data map[uint32][]byte
}

func NewFECDecoder(connID uint32) *FECDecoder {
	return &FECDecoder{
		connID: connID,
		data:   make(map[uint32][]byte),
	}
}

// ConsumeV2Packet consumes a single v2 packet and returns any recovered inner payloads.
// For TypeData it returns the carried payload immediately.
// For TypeFEC it may recover exactly one missing payload in the described group.
func (d *FECDecoder) ConsumeV2Packet(pkt []byte) (inners [][]byte) {
	h, payload, err := ParseHeader(pkt)
	if err != nil {
		return nil
	}
	if h.ConnID != d.connID {
		// Ignore unknown connIDs (future: allow migration).
		return nil
	}

	switch h.Type {
	case TypeData:
		inner := append([]byte(nil), payload...)
		d.mu.Lock()
		d.data[h.Seq] = inner
		d.mu.Unlock()
		return [][]byte{inner}

	case TypeFEC:
		// Parse parity payload.
		if len(payload) < 7 {
			return nil
		}
		baseSeq := binary.BigEndian.Uint32(payload[0:4])
		count := int(payload[4])
		maxLen := int(binary.BigEndian.Uint16(payload[5:7]))
		off := 7
		if count <= 1 || count > 32 {
			return nil
		}
		if len(payload) < off+2*count+maxLen {
			return nil
		}
		lens := make([]int, count)
		for i := 0; i < count; i++ {
			lens[i] = int(binary.BigEndian.Uint16(payload[off : off+2]))
			off += 2
		}
		xor := payload[off : off+maxLen]

		d.mu.Lock()
		defer d.mu.Unlock()

		missingIdx := -1
		for i := 0; i < count; i++ {
			seq := baseSeq + uint32(i)
			if _, ok := d.data[seq]; !ok {
				if missingIdx != -1 {
					return nil // >1 missing, can't recover with XOR
				}
				missingIdx = i
			}
		}
		if missingIdx == -1 {
			return nil // nothing to recover
		}

		// Recover the missing payload by XORing all present with the parity.
		rec := make([]byte, maxLen)
		copy(rec, xor)
		for i := 0; i < count; i++ {
			if i == missingIdx {
				continue
			}
			seq := baseSeq + uint32(i)
			p := d.data[seq]
			for j := 0; j < maxLen; j++ {
				var b byte
				if j < len(p) {
					b = p[j]
				}
				rec[j] ^= b
			}
		}

		rec = rec[:lens[missingIdx]]
		d.data[baseSeq+uint32(missingIdx)] = rec
		return [][]byte{rec}
	default:
		return nil
	}
}

