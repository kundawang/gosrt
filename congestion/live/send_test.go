package live

import (
	"net"
	"sync"
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

func mockLiveSend(onDeliver func(p packet.Packet)) *sender {
	send := NewSender(SendConfig{
		InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		DropThreshold:         10,
		OnDeliver:             onDeliver,
	})

	return send.(*sender)
}

func TestSendSequence(t *testing.T) {
	numbers := []uint32{}
	send := mockLiveSend(func(p packet.Packet) {
		numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(5)

	require.Exactly(t, []uint32{0, 1, 2, 3, 4}, numbers)

	send.Tick(10)

	require.Exactly(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, numbers)
}

func TestSendLossListACK(t *testing.T) {
	send := mockLiveSend(nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 10, send.lossList.Len())

	for i := range 10 {
		send.ACK(circular.New(uint32(i+1), packet.MAX_SEQUENCENUMBER))
		require.Equal(t, 10-(i+1), send.lossList.Len())
	}
}

func TestSendRetransmit(t *testing.T) {
	numbers := []uint32{}
	nRetransmit := 0
	send := mockLiveSend(func(p packet.Packet) {
		numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		if p.Header().RetransmittedPacketFlag {
			nRetransmit++
		}
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 0, nRetransmit)

	send.NAK([]circular.Number{
		circular.New(2, packet.MAX_SEQUENCENUMBER),
		circular.New(2, packet.MAX_SEQUENCENUMBER),
	})

	require.Equal(t, 1, nRetransmit)

	send.NAK([]circular.Number{
		circular.New(5, packet.MAX_SEQUENCENUMBER),
		circular.New(7, packet.MAX_SEQUENCENUMBER),
	})

	require.Equal(t, 4, nRetransmit)
}

func TestSendDrop(t *testing.T) {
	send := mockLiveSend(nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 10, send.lossList.Len())

	send.Tick(20)

	require.Equal(t, 0, send.lossList.Len())
}

func TestSendFlush(t *testing.T) {
	send := mockLiveSend(nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	require.Exactly(t, 10, send.packetList.Len())
	require.Exactly(t, 0, send.lossList.Len())

	send.Tick(5)

	require.Exactly(t, 5, send.packetList.Len())
	require.Exactly(t, 5, send.lossList.Len())

	send.Flush()

	require.Exactly(t, 0, send.packetList.Len())
	require.Exactly(t, 0, send.lossList.Len())
}

func mockLiveSendBandwidth(maxBW int64, dropThreshold uint64, onDeliver func(p packet.Packet)) *sender {
	send := NewSender(SendConfig{
		InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		DropThreshold:         dropThreshold,
		MaxBW:                 maxBW,
		OnDeliver:             onDeliver,
	})

	return send.(*sender)
}

func newSizedPacket(addr net.Addr, tsbpdTime uint64, size int) packet.Packet {
	p := packet.NewPacket(addr)
	p.SetData(make([]byte, size))
	p.Header().PktTsbpdTime = tsbpdTime

	return p
}

func TestSendSetBandwidth(t *testing.T) {
	send := mockLiveSend(nil)

	// No limit by default
	require.Zero(t, send.pktSndPeriod)

	// Invalid values are rejected and don't change the current limits
	require.Error(t, send.SetBandwidth(0, -1, 0))
	require.Error(t, send.SetBandwidth(0, 0, MinOverheadBW-1))
	require.Error(t, send.SetBandwidth(0, 0, MaxOverheadBW+1))
	require.Zero(t, send.pktSndPeriod)

	// Hard limit: period = (1456 + 16) * 1e6 / 1472000 = 1000us
	require.NoError(t, send.SetBandwidth(1_472_000, 0, 0))
	require.InDelta(t, 1000, send.pktSndPeriod, 1)

	// Limit derived from the input bandwidth plus overhead:
	// period = 1472 * 1e6 / (1e6 * 1.25) = 1177.6us
	require.NoError(t, send.SetBandwidth(0, 1_000_000, 25))
	require.InDelta(t, 1177.6, send.pktSndPeriod, 1)

	// A hard limit wins over the derived limit
	require.NoError(t, send.SetBandwidth(500_000, 1_000_000, 25))
	require.InDelta(t, 2944, send.pktSndPeriod, 1)

	// Zero restores the automatic mode. Without an estimate of the
	// input bandwidth, this means unlimited.
	require.NoError(t, send.SetBandwidth(0, 0, 0))
	require.Zero(t, send.pktSndPeriod)

	// In automatic mode the estimated input bandwidth plus overhead
	// defines the limit: period = 1472 * 1e6 / (2e6 * 1.2) = 613.33us
	send.rate.estimatedInputBW = 2_000_000
	require.NoError(t, send.SetBandwidth(0, 0, 20))
	require.InDelta(t, 613.33, send.pktSndPeriod, 0.1)

	// The estimated input bandwidth is bounded from below by minInputBW:
	// period = 1472 * 1e6 / (5e6 * 1.2) = 245.33us
	send.minInputBW = 5_000_000
	send.updatePktSndPeriod()
	require.InDelta(t, 245.33, send.pktSndPeriod, 0.1)

	// A negative maxBW means no limit at all
	require.NoError(t, send.SetBandwidth(-1, 1_000_000, 25))
	require.Zero(t, send.pktSndPeriod)
}

func TestSendPacing(t *testing.T) {
	numbers := []uint32{}
	send := mockLiveSendBandwidth(1_472_000, 1_000_000_000, func(p packet.Packet) {
		numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
	})

	require.InDelta(t, 1000, send.pktSndPeriod, 1)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for range 5 {
		send.Push(newSizedPacket(addr, 1, 1456))
	}

	// Only one packet per pacing period may leave
	send.Tick(1)
	require.Len(t, numbers, 1)

	send.Tick(500)
	require.Len(t, numbers, 1)

	send.Tick(1001)
	require.Len(t, numbers, 2)

	send.Tick(2000)
	require.Len(t, numbers, 3)

	send.Tick(2001)
	require.Len(t, numbers, 3)

	// Removing the limit lets the backlog drain immediately
	require.NoError(t, send.SetBandwidth(-1, 0, 0))
	send.Tick(2001)
	require.Len(t, numbers, 5)

	require.Exactly(t, []uint32{0, 1, 2, 3, 4}, numbers)
}

func TestSendPacingBacklogDrop(t *testing.T) {
	numbers := []uint32{}
	send := mockLiveSendBandwidth(1_472_000, 5_000, func(p packet.Packet) {
		numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for range 10 {
		send.Push(newSizedPacket(addr, 1, 1456))
	}

	// One packet gets sent, the rest is held back by the bandwidth limit
	send.Tick(1)
	require.Len(t, numbers, 1)
	require.Equal(t, 9, send.packetList.Len())

	// Much later, the queued packets are too old and must be dropped
	// instead of sent. The packet in the loss list is dropped as well.
	send.Tick(100_000)
	require.Len(t, numbers, 1)
	require.Equal(t, 0, send.packetList.Len())
	require.Equal(t, 0, send.lossList.Len())

	stats := send.Stats()
	require.Equal(t, uint64(10), stats.PktDrop)
	require.Equal(t, uint64(0), stats.PktBuf)
	require.Equal(t, uint64(0), stats.ByteBuf)
}

func TestSendRetransmitPacing(t *testing.T) {
	numbers := []uint32{}
	send := mockLiveSendBandwidth(1_472_000, 1_000_000_000, func(p packet.Packet) {
		numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for range 4 {
		send.Push(newSizedPacket(addr, 1, 1456))
	}

	send.Tick(1)
	send.Tick(1001)
	require.Len(t, numbers, 2)
	require.Equal(t, uint64(2000), send.nextSendTime)

	// A retransmission is sent immediately, but consumes from the same
	// bandwidth budget: the next regular packet is delayed accordingly.
	send.NAK([]circular.Number{
		circular.New(0, packet.MAX_SEQUENCENUMBER),
		circular.New(0, packet.MAX_SEQUENCENUMBER),
	})

	require.Len(t, numbers, 3)
	require.Equal(t, uint64(3000), send.nextSendTime)

	send.Tick(2001)
	require.Len(t, numbers, 3)

	send.Tick(3000)
	require.Len(t, numbers, 4)
}

func TestSendSetBandwidthConcurrent(t *testing.T) {
	send := mockLiveSendBandwidth(1_472_000, 1_000_000_000, nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	var wg sync.WaitGroup

	// Pusher
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 500 {
			send.Push(newSizedPacket(addr, uint64(i*100+1), 100))
		}
	}()

	// Ticker
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 500 {
			send.Tick(uint64(i * 100))
		}
	}()

	// Frequently switching the limits, including the automatic mode
	// and no limit
	wg.Add(1)
	go func() {
		defer wg.Done()
		limits := [][3]int64{
			{1_472_000, 0, 0},
			{0, 1_000_000, 25},
			{0, 0, 0},
			{-1, 0, 0},
		}
		for i := range 200 {
			l := limits[i%len(limits)]
			send.SetBandwidth(l[0], l[1], l[2])
		}
	}()

	// Stats and retransmission reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			send.Stats()
			send.NAK([]circular.Number{
				circular.New(uint32(i), packet.MAX_SEQUENCENUMBER),
				circular.New(uint32(i), packet.MAX_SEQUENCENUMBER),
			})
		}
	}()

	wg.Wait()
}
