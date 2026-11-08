// Package prudp is the server side of PRUDP V1, the reliable transport of NEX over UDP.
//
// Adapted from NintendoClients (c) Yannik Marchand, MIT licence: see THIRD-PARTY-NOTICES.md.
package prudp

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
)

const (
	TypeSyn        = 0
	TypeConnect    = 1
	TypeData       = 2
	TypeDisconnect = 3
	TypePing       = 4

	FlagAck      = 0x001
	FlagReliable = 0x002
	FlagNeedAck  = 0x004
	FlagHasSize  = 0x008
	FlagMultiAck = 0x200

	optionSupport       = 0
	optionConnectionSig = 1
	optionFragmentID    = 2
	optionUnreliableSeq = 3
	optionMaxSubstream  = 4

	headerSize    = 2 + 12 + 16 // magic, header, signature
	signatureSize = 16
)

var (
	errBadPacket = errors.New("invalid PRUDP packet")
	magic        = []byte{0xEA, 0xD0}
)

// Packet is one PRUDP V1 packet.
type Packet struct {
	SourcePort, SourceType uint8
	DestPort, DestType     uint8
	Type                   uint8
	Flags                  uint16
	SessionID              uint8
	SubstreamID            uint8
	PacketID               uint16
	Signature              []byte
	FragmentID             uint8
	MinorVersion           uint8
	SupportedFunctions     uint32
	MaxSubstreamID         uint8
	ConnectionSignature    []byte
	UnreliableID           uint16
	Payload                []byte
}

func (p *Packet) header(optionSize int) []byte {
	header := make([]byte, 12)
	header[0] = 1
	header[1] = uint8(optionSize)
	binary.LittleEndian.PutUint16(header[2:], uint16(len(p.Payload)))
	header[4] = p.SourcePort | p.SourceType<<4
	header[5] = p.DestPort | p.DestType<<4
	binary.LittleEndian.PutUint16(header[6:], uint16(p.Type)|p.Flags<<4)
	header[8] = p.SessionID
	header[9] = p.SubstreamID
	binary.LittleEndian.PutUint16(header[10:], p.PacketID)
	return header
}

func (p *Packet) options() []byte {
	var options []byte
	add := func(id uint8, value ...byte) {
		options = append(options, id, uint8(len(value)))
		options = append(options, value...)
	}
	switch p.Type {
	case TypeSyn, TypeConnect:
		add(optionSupport, binary.LittleEndian.AppendUint32(nil, uint32(p.MinorVersion)|p.SupportedFunctions<<8)...)
		add(optionConnectionSig, p.ConnectionSignature...)
		if p.Type == TypeConnect {
			add(optionUnreliableSeq, binary.LittleEndian.AppendUint16(nil, p.UnreliableID)...)
		}
		add(optionMaxSubstream, p.MaxSubstreamID)
	case TypeData:
		add(optionFragmentID, p.FragmentID)
	}
	return options
}

// Encode returns the datagram bytes, signature included.
func (p *Packet) Encode() []byte {
	options := p.options()
	out := make([]byte, 0, headerSize+len(options)+len(p.Payload))
	out = append(out, magic...)
	out = append(out, p.header(len(options))...)
	out = append(out, p.Signature...)
	out = append(out, options...)
	return append(out, p.Payload...)
}

// Signer computes packet signatures for one access key.
type Signer struct {
	key []byte
	sum []byte
}

// NewSigner prepares a signer.
func NewSigner(accessKey string) *Signer {
	digest := md5.Sum([]byte(accessKey))
	var total uint32
	for _, c := range []byte(accessKey) {
		total += uint32(c)
	}
	return &Signer{key: digest[:], sum: binary.LittleEndian.AppendUint32(nil, total)}
}

// Sign returns the signature of a packet under a session key and a connection signature.
func (s *Signer) Sign(p *Packet, sessionKey, connectionSignature []byte) []byte {
	options := p.options()
	digest := hmac.New(md5.New, s.key)
	digest.Write(p.header(len(options))[4:])
	digest.Write(sessionKey)
	digest.Write(s.sum)
	digest.Write(connectionSignature)
	digest.Write(options)
	digest.Write(p.Payload)
	return digest.Sum(nil)
}

func decodeOptions(data []byte, p *Packet) error {
	seen := map[uint8]bool{}
	for len(data) > 0 {
		if len(data) < 2 || len(data) < 2+int(data[1]) {
			return errBadPacket
		}
		id, value := data[0], data[2:2+int(data[1])]
		data = data[2+int(data[1]):]
		if seen[id] {
			return errBadPacket
		}
		seen[id] = true
		switch {
		case id == optionSupport && len(value) == 4:
			support := binary.LittleEndian.Uint32(value)
			p.MinorVersion, p.SupportedFunctions = uint8(support), support>>8
		case id == optionConnectionSig && len(value) == signatureSize:
			p.ConnectionSignature = value
		case id == optionFragmentID && len(value) == 1:
			p.FragmentID = value[0]
		case id == optionUnreliableSeq && len(value) == 2:
			p.UnreliableID = binary.LittleEndian.Uint16(value)
		case id == optionMaxSubstream && len(value) == 1:
			p.MaxSubstreamID = value[0]
		default:
			return errBadPacket
		}
	}
	var wanted []uint8
	switch p.Type {
	case TypeSyn:
		wanted = []uint8{optionSupport, optionConnectionSig, optionMaxSubstream}
	case TypeConnect:
		wanted = []uint8{optionSupport, optionConnectionSig, optionUnreliableSeq, optionMaxSubstream}
	case TypeData:
		wanted = []uint8{optionFragmentID}
	}
	if len(seen) != len(wanted) {
		return errBadPacket
	}
	for _, id := range wanted {
		if !seen[id] {
			return errBadPacket
		}
	}
	return nil
}

// Decode reads every packet of a datagram; one bad packet refuses it all.
func Decode(data []byte) ([]*Packet, error) {
	var packets []*Packet
	for len(data) > 0 {
		if len(data) < headerSize || data[0] != magic[0] || data[1] != magic[1] || data[2] != 1 {
			return nil, errBadPacket
		}
		optionSize := int(data[3])
		payloadSize := int(binary.LittleEndian.Uint16(data[4:]))
		if len(data) < headerSize+optionSize+payloadSize {
			return nil, errBadPacket
		}
		typeFlags := binary.LittleEndian.Uint16(data[8:])
		p := &Packet{
			SourcePort: data[6] & 0xF, SourceType: data[6] >> 4,
			DestPort: data[7] & 0xF, DestType: data[7] >> 4,
			Type: uint8(typeFlags & 0xF), Flags: typeFlags >> 4,
			SessionID: data[10], SubstreamID: data[11],
			PacketID:  binary.LittleEndian.Uint16(data[12:]),
			Signature: data[14:30],
			Payload:   data[headerSize+optionSize : headerSize+optionSize+payloadSize],
		}
		if err := decodeOptions(data[headerSize:headerSize+optionSize], p); err != nil {
			return nil, err
		}
		packets = append(packets, p)
		data = data[headerSize+optionSize+payloadSize:]
	}
	return packets, nil
}
