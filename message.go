package srt

import (
	"bytes"
	"errors"
	"io"
	"os"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
)

// Errors returned by ReadMessage and WriteMessage.
var (
	// ErrMessageAPIDisabled is returned when ReadMessage or WriteMessage is
	// called on a connection that has not been configured with MessageAPI.
	ErrMessageAPIDisabled = errors.New("srt: message API is not enabled")

	// ErrEmptyMessage is returned when a zero-length message is written, and
	// when a zero-length message is received from a peer. A message must
	// contain at least one byte.
	ErrEmptyMessage = errors.New("srt: empty message")

	// ErrMessageTooLarge is returned when a message exceeds Config.MaxMessageSize.
	// On the sending side nothing is sent. On the receiving side the message has
	// been consumed completely and is skipped.
	ErrMessageTooLarge = errors.New("srt: message exceeds the maximum message size")

	// ErrMessageTooSmall is returned by ReadMessage when the provided buffer is
	// too small for the received message. The complete message is consumed,
	// i.e. the following ReadMessage call returns the next message.
	ErrMessageTooSmall = errors.New("srt: receive buffer too small for message")

	// ErrMessageIncomplete is returned by ReadMessage when at least one packet
	// of a message was lost and could not be recovered. The rest of the message
	// is consumed, i.e. the following ReadMessage call returns the next message.
	ErrMessageIncomplete = errors.New("srt: message is incomplete, fragments were lost")
)

// maxMessageNumber is the largest value that fits into the 26 bit message
// number field of an SRT data packet. Message number 0 is reserved for FEC
// control packets and is never used for a real message.
const maxMessageNumber uint32 = 0x03FFFFFF

// maxMessageSize returns the configured upper limit for a single message.
func (c *srtConn) maxMessageSize() int {
	if c.config.MaxMessageSize == 0 {
		return int(DEFAULT_MAX_MESSAGE_SIZE)
	}

	return int(c.config.MaxMessageSize)
}

// messageResult is a completed message or the error that terminated it.
type messageResult struct {
	data []byte
	err  error
}

// messageAssembler turns the ordered stream of packets that ReadPacket returns
// into messages. It records the packet position flags (PP) and the message
// number of each packet, checks that the fragments of a message are contiguous,
// and bounds the amount of memory a single message may occupy.
//
// The assembler intentionally has no locks, the caller must serialize access.
type messageAssembler struct {
	maxSize int

	assembling    bool
	messageNumber uint32
	expectedSeq   circular.Number

	// discarding is set after the first orphan middle/last fragment of a
	// message whose first fragment was lost. The remaining fragments of that
	// message are swallowed without another error.
	discarding           bool
	discardMessageNumber uint32

	buf       bytes.Buffer
	corrupt   bool
	oversized bool
}

func newMessageAssembler(maxSize int) messageAssembler {
	return messageAssembler{maxSize: maxSize}
}

// reset drops the state of the message that is currently being assembled.
func (a *messageAssembler) reset() {
	a.assembling = false
	a.messageNumber = 0
	a.expectedSeq = circular.Number{}
	a.discarding = false
	a.discardMessageNumber = 0
	a.corrupt = false
	a.oversized = false

	// Don't keep a large buffer alive for the lifetime of the connection.
	if a.buf.Cap() > 64*1024 {
		a.buf = bytes.Buffer{}
	} else {
		a.buf.Reset()
	}
}

// append stores a fragment payload, unless the message is already known to be
// corrupt or larger than the configured limit.
func (a *messageAssembler) append(data []byte) {
	if a.corrupt || a.oversized {
		return
	}

	if a.buf.Len()+len(data) > a.maxSize {
		a.oversized = true
		return
	}

	a.buf.Write(data)
}

// follow appends a middle or last fragment in an ongoing message. It returns
// true if the message turned out to be corrupt.
func (a *messageAssembler) follow(p packet.Packet) bool {
	h := p.Header()

	// A sequence gap means that at least one fragment was dropped by the
	// receiver (too late / unrecoverable). A different message number means
	// that fragments of different messages got interleaved.
	if a.corrupt || !h.PacketSequenceNumber.Equals(a.expectedSeq) || h.MessageNumber != a.messageNumber {
		a.corrupt = true
	}

	a.expectedSeq = h.PacketSequenceNumber.Inc()

	a.append(p.Data())

	return a.corrupt
}

// push feeds one packet into the assembler and returns zero or more completed
// results. A result is either a complete message or the error why a message
// could not be delivered. Every message that terminated (completely or not)
// yields exactly one result, such that the caller can hand out results in
// send order.
func (a *messageAssembler) push(p packet.Packet) []messageResult {
	h := p.Header()

	var results []messageResult

	// A new message starts while the previous one has not been terminated.
	// The previous message is incomplete, but the new one is still valid and
	// is assembled normally.
	if a.assembling && (h.PacketPositionFlag == packet.FirstPacket || h.PacketPositionFlag == packet.SinglePacket) {
		results = append(results, messageResult{err: ErrMessageIncomplete})
		a.reset()
	}

	switch h.PacketPositionFlag {
	case packet.SinglePacket:
		a.discarding = false
		a.discardMessageNumber = 0

		data := p.Data()

		switch {
		case len(data) == 0:
			results = append(results, messageResult{err: ErrEmptyMessage})
		case len(data) > a.maxSize:
			results = append(results, messageResult{err: ErrMessageTooLarge})
		default:
			results = append(results, messageResult{data: bytes.Clone(data)})
		}

	case packet.FirstPacket:
		a.assembling = true
		a.messageNumber = h.MessageNumber
		a.expectedSeq = h.PacketSequenceNumber.Inc()
		a.discarding = false
		a.discardMessageNumber = 0
		a.buf.Reset()
		a.corrupt = false
		a.oversized = false

		a.append(p.Data())

	case packet.MiddlePacket:
		if !a.assembling {
			// The first fragment was lost. Report it once and swallow the
			// remaining fragments of the same message.
			if !a.discarding || a.discardMessageNumber != h.MessageNumber {
				a.discarding = true
				a.discardMessageNumber = h.MessageNumber
				results = append(results, messageResult{err: ErrMessageIncomplete})
			}
			break
		}

		if a.follow(p) {
			// A gap was detected, the message can't be completed anymore. The
			// error is reported right away and the remainder is swallowed.
			a.reset()
			a.discarding = true
			a.discardMessageNumber = h.MessageNumber
			results = append(results, messageResult{err: ErrMessageIncomplete})
		}

	case packet.LastPacket:
		if !a.assembling {
			if !a.discarding || a.discardMessageNumber != h.MessageNumber {
				results = append(results, messageResult{err: ErrMessageIncomplete})
			}

			a.discarding = false
			a.discardMessageNumber = 0
			break
		}

		if a.follow(p) || a.corrupt {
			results = append(results, messageResult{err: ErrMessageIncomplete})
		} else if a.oversized {
			results = append(results, messageResult{err: ErrMessageTooLarge})
		} else if a.buf.Len() == 0 {
			results = append(results, messageResult{err: ErrEmptyMessage})
		} else {
			results = append(results, messageResult{data: bytes.Clone(a.buf.Bytes())})
		}

		a.reset()
	}

	return results
}

// ReadMessage reads the next message from the connection into b. The message
// boundaries that the peer wrote with WriteMessage are preserved.
//
// If the message is larger than b, the complete message is consumed and
// ErrMessageTooSmall is returned. If a fragment of the message was lost and
// could not be recovered by retransmission or FEC, the rest of the message is
// consumed and ErrMessageIncomplete is returned. If the message is larger than
// Config.MaxMessageSize, it is consumed and ErrMessageTooLarge is returned.
//
// ReadMessage blocks until a message is available, the read deadline expires
// (see SetReadDeadline) or the connection is closed (io.EOF).
//
// ReadMessage and Read/ReadPacket must not be used on the same connection at
// the same time, as they consume the same packets.
func (c *srtConn) ReadMessage(b []byte) (int, error) {
	if !c.config.MessageAPI {
		return 0, ErrMessageAPIDisabled
	}

	c.readMessageLock.Lock()
	defer c.readMessageLock.Unlock()

	for {
		// Hand out messages that terminated while a previous packet was
		// processed (e.g. an incomplete message followed by a new one).
		if len(c.messageResults) != 0 {
			result := c.messageResults[0]
			c.messageResults = c.messageResults[1:]

			if result.err != nil {
				return 0, result.err
			}

			if len(result.data) > len(b) {
				return 0, ErrMessageTooSmall
			}

			return copy(b, result.data), nil
		}

		p, err := c.ReadPacket()
		if err != nil {
			// Packets that were already delivered to the read queue before the
			// connection closed still belong to the stream. Drain them before
			// reporting the end, such that a message is not cut off just
			// because the reader was slower than the shutdown.
			if errors.Is(err, io.EOF) {
			drain:
				for {
					select {
					case p := <-c.readQueue:
						c.messageResults = append(c.messageResults, c.messageAsm.push(p)...)
						p.Decommission()
					default:
						break drain
					}
				}

				if len(c.messageResults) != 0 {
					continue
				}

				// A message that was still being assembled when the connection
				// closed can never be completed. Report that instead of the bare
				// end of the stream, so that a truncated message is not silently
				// mistaken for a clean shutdown.
				if c.messageAsm.assembling {
					c.messageAsm.reset()
					return 0, ErrMessageIncomplete
				}
			}

			return 0, err
		}

		results := c.messageAsm.push(p)

		// The assembler has copied everything it needs.
		p.Decommission()

		c.messageResults = append(c.messageResults, results...)
	}
}

// WriteMessage writes one message to the connection. A message that does not
// fit into a single SRT data packet is split into fragments which are
// reassembled by the peer and delivered as one message again.
//
// The message is sent as an ordered sequence of packets. A zero-length message
// returns ErrEmptyMessage and a message larger than Config.MaxMessageSize
// returns ErrMessageTooLarge, in both cases nothing is sent.
//
// When an error is returned after some fragments were already queued, the
// returned byte count reflects the bytes queued. The peer will report such a
// message as incomplete (ErrMessageIncomplete).
func (c *srtConn) WriteMessage(b []byte) (int, error) {
	if !c.config.MessageAPI {
		return 0, ErrMessageAPIDisabled
	}

	if len(b) == 0 {
		return 0, ErrEmptyMessage
	}

	if len(b) > c.maxMessageSize() {
		return 0, ErrMessageTooLarge
	}

	// Serialize messages such that the fragments of a message are contiguous
	// in the packet stream and message numbers are assigned in send order.
	c.writeMessageLock.Lock()
	defer c.writeMessageLock.Unlock()

	messageNumber := c.nextMessageNumber
	c.nextMessageNumber++
	if c.nextMessageNumber > maxMessageNumber {
		c.nextMessageNumber = 1
	}

	chunkSize := len(c.writeData)
	if chunkSize < 1 {
		chunkSize = 1
	}

	// All fragments of the message share the same delivery time, such that
	// the receiver releases them in one go once the message is due.
	tsbpdTime := c.getTimestamp()

	written := 0

	for written < len(b) {
		n := min(chunkSize, len(b)-written)

		p := packet.NewPacket(nil)

		p.SetData(b[written : written+n])

		p.Header().IsControlPacket = false
		p.Header().MessageNumber = messageNumber
		// Messages are delivered in order.
		p.Header().OrderFlag = true
		p.Header().PktTsbpdTime = tsbpdTime

		remaining := len(b) - written

		switch {
		case len(b) <= chunkSize:
			p.Header().PacketPositionFlag = packet.SinglePacket
		case written == 0:
			p.Header().PacketPositionFlag = packet.FirstPacket
		case remaining <= chunkSize:
			p.Header().PacketPositionFlag = packet.LastPacket
		default:
			p.Header().PacketPositionFlag = packet.MiddlePacket
		}

		if err := c.enqueueWritePacket(p); err != nil {
			return written, err
		}

		written += n
	}

	return written, nil
}

// enqueueWritePacket puts a packet on the write queue. In contrast to the
// non-blocking stream Write it waits for space in the queue, the write
// deadline or the connection to close.
func (c *srtConn) enqueueWritePacket(p packet.Packet) error {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		deadline, deadlineChanged := c.writeDeadlineState()

		var timeoutCh <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				p.Decommission()
				return os.ErrDeadlineExceeded
			}

			if timer == nil {
				timer = time.NewTimer(d)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(d)
			}
			timeoutCh = timer.C
		}

		select {
		case <-c.ctx.Done():
			p.Decommission()
			return io.EOF
		case <-timeoutCh:
			p.Decommission()
			return os.ErrDeadlineExceeded
		case <-deadlineChanged:
			continue
		case c.writeQueue <- p:
			return nil
		}
	}
}
