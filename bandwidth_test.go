package srt

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const bwTestMsgSize = 1316

// bwTestMessage returns a message of bwTestMsgSize bytes that carries its
// sequence number and can be verified for integrity on the receiving side.
func bwTestMessage(seq uint64) []byte {
	b := make([]byte, bwTestMsgSize)
	binary.BigEndian.PutUint64(b[:8], seq)
	for i := 8; i < len(b); i++ {
		b[i] = byte(seq)
	}

	return b
}

// bwTestVerify checks the integrity of a message and returns its sequence number.
func bwTestVerify(b []byte) (uint64, bool) {
	if len(b) != bwTestMsgSize {
		return 0, false
	}

	seq := binary.BigEndian.Uint64(b[:8])
	for i := 8; i < len(b); i++ {
		if b[i] != byte(seq) {
			return seq, false
		}
	}

	return seq, true
}

// bwReceiver collects the received messages. The byte counter is cumulative,
// gaps and corrupt messages are accounted to the phase they happened in.
type bwReceiver struct {
	mu      sync.Mutex
	phase   int
	bytes   uint64
	gaps    [8]uint64
	corrupt [8]uint64
	lastSeq int64
	done    chan struct{}
}

func newBWReceiver() *bwReceiver {
	return &bwReceiver{
		lastSeq: -1,
		done:    make(chan struct{}),
	}
}

func (r *bwReceiver) setPhase(phase int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.phase = phase
}

func (r *bwReceiver) snapshot() (bytes uint64, gaps, corrupt [8]uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.bytes, r.gaps, r.corrupt
}

func (r *bwReceiver) run(conn Conn) {
	defer close(r.done)

	for {
		p, err := conn.ReadPacket()
		if err != nil {
			return
		}

		seq, ok := bwTestVerify(p.Data())

		r.mu.Lock()
		if !ok {
			r.corrupt[r.phase]++
		} else {
			if int64(seq) != r.lastSeq+1 {
				r.gaps[r.phase]++
			}
			r.lastSeq = int64(seq)
		}
		r.bytes += uint64(len(p.Data()))
		r.mu.Unlock()

		p.Decommission()
	}
}

// bwWriter writes messages at the given rate in bytes/s for the given
// duration, starting at sequence number seq. It returns the sequence number
// after the last written message.
func bwWriter(t *testing.T, conn Conn, seq uint64, rate int64, d time.Duration) uint64 {
	t.Helper()

	deadline := time.Now().Add(d)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	perTick := rate / 100 / bwTestMsgSize

	for now := range ticker.C {
		for i := int64(0); i < perTick; i++ {
			if _, err := conn.Write(bwTestMessage(seq)); err != nil {
				t.Errorf("write: %v", err)
				return seq
			}
			seq++
		}

		if now.After(deadline) {
			break
		}
	}

	return seq
}

// TestConnectionSetBandwidth verifies that the bandwidth limit of an
// established connection can be changed at runtime: the throughput follows
// the limit, the data stays intact, and removing the limit restores the
// original throughput.
func TestConnectionSetBandwidth(t *testing.T) {
	caller, listener := deadlinePair(t, "127.0.0.1:6214")

	const writeRate = 3_000_000 // writer is constantly at 3 MB/s
	const capRate = 2_000_000   // the limit under test

	recv := newBWReceiver()
	go recv.run(listener)

	var seq uint64

	// Phase 0: no limit, the receiver sees the full write rate. Both
	// snapshots are taken while writing continuously, so the constant
	// amount of in-flight data (TSBPD delay) cancels out.
	seq = bwWriter(t, caller, seq, writeRate, 300*time.Millisecond)

	bytes0, _, _ := recv.snapshot()
	start := time.Now()

	seq = bwWriter(t, caller, seq, writeRate, 900*time.Millisecond)

	bytes1, _, _ := recv.snapshot()
	rate0 := float64(bytes1-bytes0) / time.Since(start).Seconds()
	require.Greater(t, rate0, 2_500_000.0, "uncapped rate too low: %.0f B/s", rate0)

	// Phase 1: cap the bandwidth below the write rate
	require.NoError(t, caller.SetBandwidth(capRate, 0, 0))
	recv.setPhase(1)

	seq = bwWriter(t, caller, seq, writeRate, 300*time.Millisecond) // let the limit settle

	bytesBefore, _, _ := recv.snapshot()
	start = time.Now()

	seq = bwWriter(t, caller, seq, writeRate, 1200*time.Millisecond)

	bytesAfter, _, _ := recv.snapshot()
	cappedRate := float64(bytesAfter-bytesBefore) / time.Since(start).Seconds()

	// The receiver must see roughly the capped rate, not the write rate
	require.InDelta(t, capRate, cappedRate, 300_000, "capped rate: %.0f B/s", cappedRate)

	// The statistics reflect the current limit
	var stats Statistics
	caller.Stats(&stats)
	require.InDelta(t, float64(capRate)/1024/1024, stats.Instantaneous.MbpsMaxBW, 0.01)

	// Phase 2: raise the limit, the backlog drains without losses
	require.NoError(t, caller.SetBandwidth(8_000_000, 0, 0))
	recv.setPhase(2)

	seq = bwWriter(t, caller, seq, writeRate, 1000*time.Millisecond)

	// Phase 3: zero values restore the automatic mode
	require.NoError(t, caller.SetBandwidth(0, 0, 0))
	recv.setPhase(3)

	seq = bwWriter(t, caller, seq, writeRate, 800*time.Millisecond)

	// No limit at all
	require.NoError(t, caller.SetBandwidth(-1, 0, 0))

	caller.Stats(&stats)
	require.Equal(t, -1.0, stats.Instantaneous.MbpsMaxBW)

	// Phase 4: invalid values are rejected and don't break the connection
	require.Error(t, caller.SetBandwidth(0, 0, 5))
	require.Error(t, caller.SetBandwidth(0, -1, 0))
	recv.setPhase(4)

	seq = bwWriter(t, caller, seq, writeRate, 500*time.Millisecond)

	// Wait until everything has been received
	require.Eventually(t, func() bool {
		bytes, _, _ := recv.snapshot()
		return bytes >= uint64(seq)*bwTestMsgSize
	}, 5*time.Second, 50*time.Millisecond)

	caller.Close()
	listener.Close()
	<-recv.done

	_, gaps, corrupt := recv.snapshot()

	for phase := range 5 {
		require.Zero(t, corrupt[phase], "corrupt messages in phase %d", phase)
		require.Zero(t, gaps[phase], "lost messages in phase %d", phase)
	}
}

// TestConnectionSetBandwidthRace hammers an established connection with
// concurrent writes and bandwidth switches. It is meant to be run with the
// race detector enabled.
func TestConnectionSetBandwidthRace(t *testing.T) {
	caller, listener := deadlinePair(t, "127.0.0.1:6215")

	recv := newBWReceiver()
	go recv.run(listener)

	var wg sync.WaitGroup

	// Writer
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		var seq uint64
		deadline := time.Now().Add(1500 * time.Millisecond)

		for now := range ticker.C {
			for range 3 {
				if _, err := caller.Write(bwTestMessage(seq)); err != nil {
					return
				}
				seq++
			}

			if now.After(deadline) {
				return
			}
		}
	}()

	// Frequently switch the limits while writing
	wg.Add(1)
	go func() {
		defer wg.Done()

		limits := [][3]int64{
			{1_000_000, 0, 0},
			{0, 2_000_000, 25},
			{0, 0, 0},
			{-1, 0, 0},
		}

		for i := range 100 {
			l := limits[i%len(limits)]
			if err := caller.SetBandwidth(l[0], l[1], l[2]); err != nil {
				t.Errorf("set bandwidth: %v", err)
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	wg.Wait()

	// The connection is still usable
	require.NoError(t, caller.SetBandwidth(-1, 0, 0))
	_, err := caller.Write(bwTestMessage(1_000_000))
	require.NoError(t, err)

	caller.Close()
	listener.Close()
	<-recv.done

	_, _, corrupt := recv.snapshot()
	require.Zero(t, corrupt[0], "corrupt messages")
}

// TestConnectionSetBandwidthClosed verifies that updating the bandwidth
// limits of a closed connection fails deterministically.
func TestConnectionSetBandwidthClosed(t *testing.T) {
	caller, listener := deadlinePair(t, "127.0.0.1:6216")

	caller.Close()

	err := caller.SetBandwidth(1_000_000, 0, 0)
	require.Error(t, err)
	require.True(t, errors.Is(err, net.ErrClosed), "error: %v", err)

	listener.Close()
}
