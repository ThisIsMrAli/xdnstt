package dnstt_client

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// ClientMetrics tracks high-level tunnel statistics.
// All fields are updated atomically and safe for concurrent use.
type ClientMetrics struct {
	QueriesSent  atomic.Uint64
	QueriesRecv  atomic.Uint64
	BytesSent    atomic.Uint64
	BytesRecv    atomic.Uint64
	CurrentEDNS0 atomic.Uint32 // last advertised EDNS0 size
}

// Metrics is the package-level client metrics instance.
var Metrics ClientMetrics

// StartMetricsLogger starts a background goroutine that logs tunnel statistics
// every interval. It exits when done is closed.
func StartMetricsLogger(interval time.Duration, done <-chan struct{}) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()

		var prevSent, prevRecv, prevBSent, prevBRecv uint64

		for {
			select {
			case <-done:
				return
			case <-t.C:
				sent := Metrics.QueriesSent.Load()
				recv := Metrics.QueriesRecv.Load()
				bsent := Metrics.BytesSent.Load()
				brecv := Metrics.BytesRecv.Load()
				edns0 := Metrics.CurrentEDNS0.Load()

				log.Printf("[metrics] queries Δ+%d/+%d (Σ%d/%d) | bytes Δ+%s/+%s | edns0: %d",
					sent-prevSent, recv-prevRecv,
					sent, recv,
					humanBytes(bsent-prevBSent), humanBytes(brecv-prevBRecv),
					edns0)

				prevSent, prevRecv = sent, recv
				prevBSent, prevBRecv = bsent, brecv
			}
		}
	}()
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
