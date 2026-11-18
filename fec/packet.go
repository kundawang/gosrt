package fec

import (
	"encoding/binary"
	"fmt"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
)

// ExtraHeaderSize is the size of the extra FEC header in bytes.
const ExtraHeaderSize = 4

// MessageMetadataSize is the size of the optional message metadata extension.
// It is appended after the payload recovery data and carries the XOR of the
// packed message metadata of all packets in the row. The presence of the
// extension is marked with FlagMessageMetadata in the FEC header. FEC control
// packets created by other implementations don't carry it; in that case the
// packet position and message number of a recovered packet are unknown.
const MessageMetadataSize = 4

// FlagMessageMetadata marks a FEC control packet that carries the message
// metadata extension. The flags of the FEC header are defined to only hold the
// encryption flags in the lower two bits, the other bits are unused.
const FlagMessageMetadata uint8 = 1 << 7

// packMessageMetadata packs the packet position, the order flag and the
// message number into a single word such that the word can be XOR'ed.
func packMessageMetadata(position packet.PacketPosition, order bool, messageNumber uint32) uint32 {
	word := messageNumber & 0x03FFFFFF
	if order {
		word |= 1 << 26
	}
	word |= (position.Val() & 0b11) << 27

	return word
}

// unpackMessageMetadata extracts the message metadata from a word.
func unpackMessageMetadata(word uint32) (packet.PacketPosition, bool, uint32) {
	return packet.PacketPosition(word >> 27 & 0b11), word&(1<<26) != 0, word & 0x03FFFFFF
}

// ControlPacket holds the parsed fields of an FEC control packet.
type ControlPacket struct {
	SNBase         uint32
	TimestampRecov uint32
	GroupIndex     int8
	FlagsRecov     uint8
	LengthRecov    uint16
	PayloadRecov   []byte

	// HasMessageMetadata states whether MessageMetadataRecov is valid.
	HasMessageMetadata bool

	// MessageMetadataRecov is the XOR of the packed message metadata of all
	// data packets in the row.
	MessageMetadataRecov uint32
}

// IsControlPacket checks if a packet is an FEC control packet.
func IsControlPacket(p packet.Packet) bool {
	return !p.Header().IsControlPacket && p.Header().MessageNumber == 0
}

// ParseControlPacket parses a gosrt packet into an FEC ControlPacket.
func ParseControlPacket(p packet.Packet) (*ControlPacket, error) {
	if !IsControlPacket(p) {
		return nil, fmt.Errorf("not an FEC control packet")
	}

	payload := p.Data()
	if len(payload) < ExtraHeaderSize {
		return nil, fmt.Errorf("FEC control packet payload too small")
	}

	ctrl := &ControlPacket{
		SNBase:         p.Header().PacketSequenceNumber.Val(),
		TimestampRecov: p.Header().Timestamp, // In FEC packets, Timestamp is Timestamp Recovery
		GroupIndex:     int8(payload[0]),
		FlagsRecov:     payload[1],
		LengthRecov:    binary.BigEndian.Uint16(payload[2:4]),
		PayloadRecov:   make([]byte, len(payload)-ExtraHeaderSize),
	}

	copy(ctrl.PayloadRecov, payload[ExtraHeaderSize:])

	if ctrl.FlagsRecov&FlagMessageMetadata != 0 {
		if len(ctrl.PayloadRecov) < MessageMetadataSize {
			return nil, fmt.Errorf("FEC control packet with message metadata is too small")
		}

		ctrl.HasMessageMetadata = true
		ctrl.FlagsRecov &^= FlagMessageMetadata
		ctrl.MessageMetadataRecov = binary.BigEndian.Uint32(ctrl.PayloadRecov[len(ctrl.PayloadRecov)-MessageMetadataSize:])
		ctrl.PayloadRecov = ctrl.PayloadRecov[:len(ctrl.PayloadRecov)-MessageMetadataSize]
	}

	return ctrl, nil
}

// WriteControlPacket builds an FEC control packet and returns it.
func WriteControlPacket(destSocketId uint32, ctrl *ControlPacket) packet.Packet {
	p := packet.NewPacket(nil)
	p.Header().IsControlPacket = false
	p.Header().PacketSequenceNumber = circular.New(ctrl.SNBase, packet.MAX_SEQUENCENUMBER)
	p.Header().MessageNumber = 0
	p.Header().Timestamp = ctrl.TimestampRecov
	p.Header().DestinationSocketId = destSocketId

	// Flags for FEC control packet according to spec
	p.Header().PacketPositionFlag = packet.SinglePacket         // 11b
	p.Header().OrderFlag = true                                 // Live mode typical
	p.Header().KeyBaseEncryptionFlag = packet.UnencryptedPacket // 00b
	p.Header().RetransmittedPacketFlag = true                   // Must be 1 to prevent reordering logic

	size := ExtraHeaderSize + len(ctrl.PayloadRecov)
	if ctrl.HasMessageMetadata {
		size += MessageMetadataSize
	}

	payload := make([]byte, size)

	// Write Extra FEC header
	payload[0] = byte(ctrl.GroupIndex)
	payload[1] = ctrl.FlagsRecov
	if ctrl.HasMessageMetadata {
		payload[1] |= FlagMessageMetadata
	}
	binary.BigEndian.PutUint16(payload[2:4], ctrl.LengthRecov)

	// Write payload recovery
	copy(payload[4:], ctrl.PayloadRecov)

	if ctrl.HasMessageMetadata {
		binary.BigEndian.PutUint32(payload[ExtraHeaderSize+len(ctrl.PayloadRecov):], ctrl.MessageMetadataRecov)
	}

	p.SetData(payload)

	return p
}
