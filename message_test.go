package srt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/fec"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

// messagePair returns a connected pair of connections. The caller is dialed
// with callerCfg, the accepted connection uses the listener's config.
func messagePair(t *testing.T, callerCfg, listenerCfg Config) (Conn, Conn) {
	t.Helper()

	ln, err := Listen("srt", "127.0.0.1:0", listenerCfg)
	require.NoError(t, err)
	t.Cleanup(ln.Close)

	accepted := make(chan Conn, 1)
	go func() {
		req, err := ln.Accept2()
		if err != nil {
			return
		}
		conn, err := req.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	client, err := Dial("srt", ln.Addr().String(), callerCfg)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	var server Conn
	select {
	case server = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not accepted")
	}
	t.Cleanup(func() { server.Close() })

	return client, server
}

func messageConfig() Config {
	cfg := DefaultConfig()
	cfg.MessageAPI = true
	return cfg
}

// readMessages reads exactly n messages of at most size bytes.
func readMessages(t *testing.T, conn Conn, n, size int) [][]byte {
	t.Helper()

	messages := make([][]byte, 0, n)
	buf := make([]byte, size)

	for range n {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		m, err := conn.ReadMessage(buf)
		require.NoError(t, err)
		messages = append(messages, bytes.Clone(buf[:m]))
	}

	return messages
}

func TestMessageAPIDisabled(t *testing.T) {
	cfg := DefaultConfig()
	client, server := messagePair(t, cfg, cfg)

	_, err := client.WriteMessage([]byte("hello"))
	require.ErrorIs(t, err, ErrMessageAPIDisabled)

	_, err = server.ReadMessage(make([]byte, 10))
	require.ErrorIs(t, err, ErrMessageAPIDisabled)
}

func TestMessageAPIWriteErrors(t *testing.T) {
	cfg := messageConfig()
	cfg.MaxMessageSize = 1024
	client, _ := messagePair(t, cfg, cfg)

	n, err := client.WriteMessage(nil)
	require.ErrorIs(t, err, ErrEmptyMessage)
	require.Zero(t, n)

	n, err = client.WriteMessage([]byte{})
	require.ErrorIs(t, err, ErrEmptyMessage)
	require.Zero(t, n)

	n, err = client.WriteMessage(make([]byte, 1025))
	require.ErrorIs(t, err, ErrMessageTooLarge)
	require.Zero(t, n)

	// A message exactly at the limit is accepted.
	n, err = client.WriteMessage(bytes.Repeat([]byte{'x'}, 1024))
	require.NoError(t, err)
	require.Equal(t, 1024, n)
}

func TestMessageAPIShortMessages(t *testing.T) {
	cfg := messageConfig()
	client, server := messagePair(t, cfg, cfg)

	// Subtitle cues are typical short messages with a delimiter that must not
	// be used to infer boundaries.
	messages := [][]byte{
		[]byte("one subtitle cue"),
		[]byte("a"),
		[]byte("line one\nline two\n"),
		[]byte("{\\an8}Hello World"),
		[]byte("\x00\x01\x02binary\x00"),
	}

	for _, m := range messages {
		n, err := client.WriteMessage(m)
		require.NoError(t, err)
		require.Equal(t, len(m), n)
	}

	got := readMessages(t, server, len(messages), 2048)

	for i := range messages {
		require.Equal(t, messages[i], got[i], "message %d", i)
	}
}

func TestMessageAPIFragmentedMessages(t *testing.T) {
	cfg := messageConfig()
	client, server := messagePair(t, cfg, cfg)

	// Sizes around the fragment boundary and up to a large message.
	messages := [][]byte{
		bytes.Repeat([]byte{'A'}, 3000),
		bytes.Repeat([]byte{'B'}, int(MAX_PAYLOAD_SIZE)),
		bytes.Repeat([]byte{'C'}, int(MAX_PAYLOAD_SIZE)+1),
		bytes.Repeat([]byte{'D'}, 100_000),
		[]byte("short after large"),
	}

	for i, m := range messages {
		// Make every message distinguishable.
		m[0] = byte('a' + i)

		n, err := client.WriteMessage(m)
		require.NoError(t, err)
		require.Equal(t, len(m), n)
	}

	got := readMessages(t, server, len(messages), 200_000)

	for i := range messages {
		require.Len(t, got[i], len(messages[i]), "message %d length", i)
		require.True(t, bytes.Equal(messages[i], got[i]), "message %d content", i)
	}
}

func TestMessageAPIBufferTooSmall(t *testing.T) {
	cfg := messageConfig()
	client, server := messagePair(t, cfg, cfg)

	require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err := client.WriteMessage([]byte("this message does not fit"))
	require.NoError(t, err)

	_, err = client.WriteMessage([]byte("next"))
	require.NoError(t, err)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := server.ReadMessage(make([]byte, 4))
	require.ErrorIs(t, err, ErrMessageTooSmall)
	require.Zero(t, n)

	// The complete message has been consumed, the next one is returned.
	buf := make([]byte, 16)
	n, err = server.ReadMessage(buf)
	require.NoError(t, err)
	require.Equal(t, "next", string(buf[:n]))
}

func TestMessageAPIMaxMessageSizeReceive(t *testing.T) {
	senderCfg := messageConfig()
	senderCfg.MaxMessageSize = 100_000

	receiverCfg := messageConfig()
	receiverCfg.MaxMessageSize = 64

	// Each side enforces its own limit; nothing is negotiated.
	client, server := messagePair(t, senderCfg, receiverCfg)

	require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err := client.WriteMessage(bytes.Repeat([]byte("x"), 1000))
	require.NoError(t, err)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = server.ReadMessage(make([]byte, 100))
	require.ErrorIs(t, err, ErrMessageTooLarge)

	// The following message is delivered normally.
	_, err = client.WriteMessage([]byte("small"))
	require.NoError(t, err)

	buf := make([]byte, 16)
	n, err := server.ReadMessage(buf)
	require.NoError(t, err)
	require.Equal(t, "small", string(buf[:n]))
}

func TestMessageAPIReadTimeout(t *testing.T) {
	cfg := messageConfig()
	_, server := messagePair(t, cfg, cfg)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	start := time.Now()
	_, err := server.ReadMessage(make([]byte, 16))
	requireTimeout(t, err)
	require.InDelta(t, 100*time.Millisecond, time.Since(start), float64(80*time.Millisecond))
}

func TestMessageAPIWriteTimeout(t *testing.T) {
	cfg := messageConfig()
	client, _ := messagePair(t, cfg, cfg)

	// A deadline in the past fails immediately.
	require.NoError(t, client.SetWriteDeadline(time.Now().Add(-time.Second)))
	_, err := client.WriteMessage([]byte("hello"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestMessageAPICloseUnblocksRead(t *testing.T) {
	cfg := messageConfig()
	client, server := messagePair(t, cfg, cfg)

	result := make(chan error, 1)
	go func() {
		_, err := server.ReadMessage(make([]byte, 16))
		result <- err
	}()

	time.Sleep(50 * time.Millisecond)
	client.Close()

	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMessage was not unblocked by Close")
	}
}

// TestMessageAPICloseMidMessage verifies that a message that was cut off by the
// connection closing is reported as incomplete rather than as a clean end.
func TestMessageAPICloseMidMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("proxy test")
	}

	proxy, err := newDropProxy("127.0.0.1:6224", "127.0.0.1:6225", false)
	require.NoError(t, err)
	defer proxy.Close()

	client, server := proxyPair(t, proxy, "127.0.0.1:6225", 100*time.Millisecond)
	warmup(t, client, server)

	// Forward the first fragment of the next message and drop all following
	// data packets, such that only the start of the message arrives.
	proxy.arm()
	proxy.lock.Lock()
	proxy.forwardFirst = true
	proxy.lock.Unlock()

	dl := client.(*dialer)
	dl.connLock.RLock()
	width := len(dl.conn.writeData)
	dl.connLock.RUnlock()

	_, err = client.WriteMessage(bytes.Repeat([]byte("x"), width*3))
	require.NoError(t, err)

	// Give the receiver time to assemble the first fragment.
	time.Sleep(200 * time.Millisecond)
	client.Close()

	require.NoError(t, server.SetReadDeadline(time.Now().Add(2*time.Second)))

	_, err = server.ReadMessage(make([]byte, width*4))
	require.ErrorIs(t, err, ErrMessageIncomplete)
}

// TestMessageAPIStreamUnchanged verifies that Read and Write keep their
// original byte stream behavior when message mode is enabled.
func TestMessageAPIStreamUnchanged(t *testing.T) {
	cfg := messageConfig()
	client, server := messagePair(t, cfg, cfg)

	payload := bytes.Repeat([]byte("stream"), 2000)

	require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
	n, err := client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	got := make([]byte, len(payload))
	_, err = io.ReadFull(server, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

// TestMessageAPIPacketLayout inspects the packets that WriteMessage produces on
// a connection that is not attached to a network.
func TestMessageAPIPacketLayout(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	cfg := messageConfig()

	var lock sync.Mutex
	var sent []packet.Packet

	c := newSRTConn(srtConnConfig{
		version:                     5,
		isCaller:                    true,
		localAddr:                   addr,
		remoteAddr:                  addr,
		config:                      cfg,
		start:                       time.Now(),
		socketId:                    1,
		peerSocketId:                2,
		tsbpdTimeBase:               0,
		tsbpdDelay:                  uint64((120 * time.Millisecond).Microseconds()),
		peerTsbpdDelay:              uint64((120 * time.Millisecond).Microseconds()),
		initialPacketSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		onSend: func(p packet.Packet) {
			if p.Header().IsControlPacket {
				return
			}
			lock.Lock()
			defer lock.Unlock()
			sent = append(sent, p.Clone())
		},
		onShutdown: func(*srtConn) {},
		logger:     NewLogger(nil),
	})
	defer c.Close()

	message := bytes.Repeat([]byte("z"), len(c.writeData)*2+10)
	n, err := c.WriteMessage(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)

	require.Eventually(t, func() bool {
		lock.Lock()
		defer lock.Unlock()
		return len(sent) >= 3
	}, 5*time.Second, 10*time.Millisecond)

	lock.Lock()
	pkts := append([]packet.Packet(nil), sent...)
	lock.Unlock()

	require.GreaterOrEqual(t, len(pkts), 3)

	for _, p := range pkts {
		require.Equal(t, pkts[0].Header().MessageNumber, p.Header().MessageNumber)
		require.NotZero(t, p.Header().MessageNumber)
		require.True(t, p.Header().OrderFlag)
		require.Equal(t, pkts[0].Header().PktTsbpdTime, p.Header().PktTsbpdTime)
		require.LessOrEqual(t, p.Len(), uint64(len(c.writeData)))
	}

	require.Equal(t, packet.FirstPacket, pkts[0].Header().PacketPositionFlag)
	for _, p := range pkts[1 : len(pkts)-1] {
		require.Equal(t, packet.MiddlePacket, p.Header().PacketPositionFlag)
	}
	require.Equal(t, packet.LastPacket, pkts[len(pkts)-1].Header().PacketPositionFlag)
}

// dropProxy is a UDP proxy between a caller and a listener. It can drop the
// first copy or all copies of a selected data packet.
type dropProxy struct {
	conn   *net.UDPConn
	toAddr *net.UDPAddr
	from   *net.UDPAddr

	lock sync.Mutex

	armed           bool
	nPackets        int
	target          uint32
	hasTarget       bool
	dropAll         bool
	droppedOriginal bool

	// forwardFirst drops every data packet after the first one that arrives
	// once the proxy is armed. Used to emulate a connection that dies while a
	// message is being transmitted.
	forwardFirst bool
}

func newDropProxy(listenAddr, forwardAddr string, dropAll bool) (*dropProxy, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	toAddr, err := net.ResolveUDPAddr("udp", forwardAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	p := &dropProxy{
		conn:    conn,
		toAddr:  toAddr,
		dropAll: dropAll,
	}

	go p.loop()

	return p, nil
}

func (p *dropProxy) Close() {
	p.conn.Close()
}

func (p *dropProxy) arm() {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.armed = true
	p.nPackets = 0
	p.hasTarget = false
	p.droppedOriginal = false
}

// loop forwards packets in both directions and implements the drop policy for
// data packets that travel from the caller to the listener.
func (p *dropProxy) loop() {
	buf := make([]byte, 2048)

	for {
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		data := bytes.Clone(buf[:n])

		p.lock.Lock()

		if p.from == nil {
			p.from = addr
		}

		drop := false

		if addr.String() != p.from.String() {
			// From the listener to the caller.
			if p.from != nil {
				p.conn.WriteToUDP(data, p.from)
			}
			p.lock.Unlock()
			continue
		}

		// From the caller to the listener.
		if p.armed && n >= 16 && data[0]&0x80 == 0 && n > 16 {
			sn := binary.BigEndian.Uint32(data[0:])
			retrans := data[4]&0b100 != 0

			if p.forwardFirst {
				// Forward only the first data packet after arming.
				if p.hasTarget {
					drop = true
				} else {
					p.hasTarget = true
				}
			} else if !p.hasTarget {
				if p.nPackets == 1 {
					// The second data packet is the middle fragment of the
					// message sent after arming.
					p.target = sn
					p.hasTarget = true

					if p.dropAll || !retrans {
						drop = true
						p.droppedOriginal = true
					}
				}
				p.nPackets++
			} else if sn == p.target {
				if p.dropAll || (!retrans && !p.droppedOriginal) {
					drop = true
					p.droppedOriginal = true
				}
			}
		}

		if !drop {
			p.conn.WriteToUDP(data, p.toAddr)
		}

		p.lock.Unlock()
	}
}

func proxyPair(t *testing.T, proxy *dropProxy, serverAddr string, latency time.Duration) (Conn, Conn) {
	t.Helper()

	serverCfg := messageConfig()
	serverCfg.Latency = latency
	serverCfg.PeerLatency = latency

	ln, err := Listen("srt", serverAddr, serverCfg)
	require.NoError(t, err)
	t.Cleanup(ln.Close)

	accepted := make(chan Conn, 1)
	go func() {
		req, err := ln.Accept2()
		if err != nil {
			return
		}
		conn, err := req.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	clientCfg := messageConfig()
	clientCfg.Latency = latency
	clientCfg.PeerLatency = latency

	client, err := Dial("srt", proxy.conn.LocalAddr().String(), clientCfg)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	var server Conn
	select {
	case server = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not accepted")
	}
	t.Cleanup(func() { server.Close() })

	return client, server
}

func warmup(t *testing.T, client, server Conn) {
	t.Helper()

	require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err := client.WriteMessage([]byte("warmup"))
	require.NoError(t, err)

	buf := make([]byte, 32)
	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := server.ReadMessage(buf)
	require.NoError(t, err)
	require.Equal(t, "warmup", string(buf[:n]))
}

// TestMessageAPIWithFEC sends messages while FEC is enabled and verifies that
// the message boundaries are preserved and the data fits into the payload size
// although the FEC control packets need room for their own header.
func TestMessageAPIWithFEC(t *testing.T) {
	cfg := messageConfig()
	cfg.PacketFilter = "fec,cols:5,rows:1,layout:even"
	client, server := messagePair(t, cfg, cfg)

	messages := [][]byte{
		bytes.Repeat([]byte("A"), 3000),
		[]byte("short"),
		bytes.Repeat([]byte("B"), int(MAX_PAYLOAD_SIZE)+100),
	}

	for _, m := range messages {
		n, err := client.WriteMessage(m)
		require.NoError(t, err)
		require.Equal(t, len(m), n)
	}

	got := readMessages(t, server, len(messages), 8192)

	for i := range messages {
		require.True(t, bytes.Equal(messages[i], got[i]), "message %d", i)
	}
}

// TestMessageAPIRetransmittedFragment checks that a lost fragment that is
// recovered by retransmission yields the message exactly once.
func TestMessageAPIRetransmittedFragment(t *testing.T) {
	if testing.Short() {
		t.Skip("proxy test")
	}

	proxy, err := newDropProxy("127.0.0.1:6220", "127.0.0.1:6221", false)
	require.NoError(t, err)
	defer proxy.Close()

	client, server := proxyPair(t, proxy, "127.0.0.1:6221", 300*time.Millisecond)
	warmup(t, client, server)

	// Drop the first copy of the middle fragment. The retransmission is
	// forwarded and must not result in a duplicate or a truncated message.
	proxy.arm()

	fragmented := bytes.Repeat([]byte("f"), 4000)
	require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err = client.WriteMessage(fragmented)
	require.NoError(t, err)
	_, err = client.WriteMessage([]byte("after"))
	require.NoError(t, err)

	got := readMessages(t, server, 2, 8192)
	require.Equal(t, fragmented, got[0])
	require.Equal(t, []byte("after"), got[1])
}

// TestMessageAPIUnrecoverableFragment checks that a fragment which is lost for
// good is reported as ErrMessageIncomplete exactly once, and that following
// messages are still delivered with correct boundaries.
func TestMessageAPIUnrecoverableFragment(t *testing.T) {
	if testing.Short() {
		t.Skip("proxy test")
	}

	proxy, err := newDropProxy("127.0.0.1:6222", "127.0.0.1:6223", true)
	require.NoError(t, err)
	defer proxy.Close()

	client, server := proxyPair(t, proxy, "127.0.0.1:6223", 80*time.Millisecond)
	warmup(t, client, server)

	proxy.arm()

	// Every copy of the middle fragment is dropped.
	_, err = client.WriteMessage(bytes.Repeat([]byte("g"), 4000))
	require.NoError(t, err)
	_, err = client.WriteMessage([]byte("after"))
	require.NoError(t, err)

	buf := make([]byte, 8192)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := server.ReadMessage(buf)
	require.ErrorIs(t, err, ErrMessageIncomplete)
	require.Zero(t, n)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err = server.ReadMessage(buf)
	require.NoError(t, err)
	require.Equal(t, "after", string(buf[:n]))
}

func mkPacket(addr net.Addr, seq, messageNumber uint32, pos packet.PacketPosition, data []byte) packet.Packet {
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(seq, packet.MAX_SEQUENCENUMBER)
	p.Header().MessageNumber = messageNumber
	p.Header().PacketPositionFlag = pos
	if len(data) != 0 {
		p.SetData(data)
	}
	return p
}

func TestMessageAssemblerRetransmissionAndOrder(t *testing.T) {
	addr := &testAddr{"127.0.0.1:1"}
	asm := newMessageAssembler(1 << 20)

	first := mkPacket(addr, 10, 5, packet.FirstPacket, []byte("abc"))
	middle := mkPacket(addr, 11, 5, packet.MiddlePacket, []byte("def"))
	middle.Header().RetransmittedPacketFlag = true
	last := mkPacket(addr, 12, 5, packet.LastPacket, []byte("ghi"))

	// Fragments are delivered in sequence, possibly as retransmissions.
	require.Empty(t, asm.push(first))
	require.Empty(t, asm.push(middle))

	results := asm.push(last)
	require.Len(t, results, 1)
	require.NoError(t, results[0].err)
	require.Equal(t, "abcdefghi", string(results[0].data))
}

func TestMessageAssemblerMissingFragment(t *testing.T) {
	addr := &testAddr{"127.0.0.1:1"}
	asm := newMessageAssembler(1 << 20)

	require.Empty(t, asm.push(mkPacket(addr, 10, 5, packet.FirstPacket, []byte("abc"))))
	// Sequence 11 is missing. The gap is detected with the next fragment and
	// the error is reported right away.
	results := asm.push(mkPacket(addr, 12, 5, packet.MiddlePacket, []byte("ghi")))
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, ErrMessageIncomplete)

	// The remaining fragments of the broken message are swallowed.
	require.Empty(t, asm.push(mkPacket(addr, 13, 5, packet.LastPacket, []byte("jkl"))))

	// The assembler is ready for the next message.
	results = asm.push(mkPacket(addr, 14, 6, packet.SinglePacket, []byte("next")))
	require.Len(t, results, 1)
	require.NoError(t, results[0].err)
	require.Equal(t, "next", string(results[0].data))
}

func TestMessageAssemblerInterleavedMessages(t *testing.T) {
	addr := &testAddr{"127.0.0.1:1"}
	asm := newMessageAssembler(1 << 20)

	require.Empty(t, asm.push(mkPacket(addr, 10, 5, packet.FirstPacket, []byte("abc"))))

	// A new message starts although the previous one is not finished.
	results := asm.push(mkPacket(addr, 12, 6, packet.FirstPacket, []byte("xyz")))
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, ErrMessageIncomplete)

	results = asm.push(mkPacket(addr, 13, 6, packet.LastPacket, []byte("123")))
	require.Len(t, results, 1)
	require.NoError(t, results[0].err)
	require.Equal(t, "xyz123", string(results[0].data))
}

func TestMessageAssemblerEmptyAndOrphanFragments(t *testing.T) {
	addr := &testAddr{"127.0.0.1:1"}
	asm := newMessageAssembler(1 << 20)

	// An empty single packet message.
	results := asm.push(mkPacket(addr, 10, 5, packet.SinglePacket, nil))
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, ErrEmptyMessage)

	// A middle fragment without a first fragment is reported once, the
	// remaining fragments of the same message are swallowed.
	results = asm.push(mkPacket(addr, 11, 6, packet.MiddlePacket, []byte("abc")))
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, ErrMessageIncomplete)

	results = asm.push(mkPacket(addr, 12, 6, packet.MiddlePacket, []byte("abc")))
	require.Empty(t, results)

	results = asm.push(mkPacket(addr, 13, 6, packet.LastPacket, []byte("abc")))
	require.Empty(t, results)

	// A last fragment without any preceding fragment is reported once.
	results = asm.push(mkPacket(addr, 14, 7, packet.LastPacket, []byte("abc")))
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, ErrMessageIncomplete)

	// Empty fragments add up to an empty message.
	require.Empty(t, asm.push(mkPacket(addr, 15, 8, packet.FirstPacket, nil)))
	results = asm.push(mkPacket(addr, 16, 8, packet.LastPacket, nil))
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, ErrEmptyMessage)
}

func TestMessageAssemblerOversized(t *testing.T) {
	addr := &testAddr{"127.0.0.1:1"}
	asm := newMessageAssembler(16)

	require.Empty(t, asm.push(mkPacket(addr, 10, 5, packet.FirstPacket, []byte("0123456789"))))
	require.Empty(t, asm.push(mkPacket(addr, 11, 5, packet.MiddlePacket, []byte("0123456789"))))

	results := asm.push(mkPacket(addr, 12, 5, packet.LastPacket, []byte("0123456789")))
	require.Len(t, results, 1)
	require.ErrorIs(t, results[0].err, ErrMessageTooLarge)

	// The oversized message consumed, the next one is fine.
	results = asm.push(mkPacket(addr, 13, 6, packet.SinglePacket, []byte("ok")))
	require.Len(t, results, 1)
	require.NoError(t, results[0].err)
	require.Equal(t, "ok", string(results[0].data))
}

// TestFECPreservesMessageMetadata checks that a packet recovered by FEC keeps
// its fragment position and message number, such that message boundaries
// survive FEC recovery.
func TestFECPreservesMessageMetadata(t *testing.T) {
	addr := &testAddr{"127.0.0.1:1"}

	gen := fec.NewGenerator(fec.Config{Cols: 2, Rows: 1, Layout: "even"})

	first := mkPacket(addr, 3, 42, packet.FirstPacket, []byte("ab"))
	first.Header().OrderFlag = true
	first.Header().Timestamp = 1000

	middle := mkPacket(addr, 4, 42, packet.MiddlePacket, []byte("cd"))
	middle.Header().OrderFlag = true
	middle.Header().Timestamp = 1000

	require.Empty(t, gen.AddPacket(first))
	fecPkts := gen.AddPacket(middle)
	// The row is generated with the second AddPacket, covering seq 3 and 4.
	require.Len(t, fecPkts, 1)

	ctrl, err := fec.ParseControlPacket(fecPkts[0])
	require.NoError(t, err)
	require.True(t, ctrl.HasMessageMetadata)

	// Feed the first fragment and the control packet. The middle fragment is
	// recovered.
	rec := fec.NewReconstructor(fec.Config{Cols: 2, Rows: 1, Layout: "even"})
	require.Empty(t, rec.AddPacket(first))

	recovered := rec.AddPacket(fecPkts[0])
	require.Len(t, recovered, 1)

	rp := recovered[0]
	require.Equal(t, uint32(4), rp.Header().PacketSequenceNumber.Val())
	require.Equal(t, uint32(42), rp.Header().MessageNumber)
	require.Equal(t, packet.MiddlePacket, rp.Header().PacketPositionFlag)
	require.True(t, rp.Header().OrderFlag)
	require.Equal(t, []byte("cd"), rp.Data())

	// The recovered fragment completes the message together with the last
	// fragment, i.e. FEC recovery does not break the message boundary.
	last := mkPacket(addr, 5, 42, packet.LastPacket, []byte("ef"))
	last.Header().OrderFlag = true

	asm := newMessageAssembler(1 << 20)
	require.Empty(t, asm.push(first))
	require.Empty(t, asm.push(rp))

	results := asm.push(last)
	require.Len(t, results, 1)
	require.NoError(t, results[0].err)
	require.Equal(t, "abcdef", string(results[0].data))
}

func TestMessageAPIErrorsAreDistinct(t *testing.T) {
	errs := []error{
		ErrMessageAPIDisabled,
		ErrEmptyMessage,
		ErrMessageTooLarge,
		ErrMessageTooSmall,
		ErrMessageIncomplete,
	}

	for i := range errs {
		for j := range errs {
			if i == j {
				continue
			}
			require.False(t, errors.Is(errs[i], errs[j]))
		}
	}
}

// testAddr is a net.Addr for unit tests.
type testAddr struct {
	s string
}

func (a *testAddr) Network() string { return "test" }
func (a *testAddr) String() string  { return a.s }
