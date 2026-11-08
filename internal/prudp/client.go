package prudp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/logx"
)

const (
	fragmentSize  = 1300
	windowSize    = 1024    // packets accepted ahead of the next expected one
	queueSize     = 256     // messages waiting for the handler
	maxMessage    = 1 << 20 // reassembled message
	defaultRC4Key = "CD&ML"
)

type pendingKey struct {
	kind uint8
	id   uint16
}

type pending struct {
	data   []byte
	next   time.Time
	resent int
}

// Client is one connection, seen from the server.
type Client struct {
	server        *Server
	key           clientKey
	localSession  uint8
	remoteSession uint8
	remoteSig     []byte
	minor         uint8
	pid           uint32
	cid           uint32
	sessionKey    []byte

	connectPacket   []byte // a resent CONNECT is the same packet
	connectResponse []byte

	queue  chan []byte
	closed chan struct{}

	mu            sync.Mutex
	disconnected  bool
	disconnecting bool
	encrypt       *rc4.Cipher
	decrypt       *rc4.Cipher
	nextID        uint16 // shared by DATA and reliable PING
	expected      uint16
	window        map[uint16]*Packet
	fragments     []byte
	unacked       map[pendingKey]*pending
	lastSeen      time.Time
	nextPing      time.Time
	gaveUpAt      time.Time
}

func newClient(s *Server, key clientKey, connect *Packet, login *loginResult) *Client {
	now := time.Now()
	rc4Key := login.sessionKey
	if rc4Key == nil {
		rc4Key = []byte(defaultRC4Key)
	}
	encrypt, _ := rc4.NewCipher(rc4Key)
	decrypt, _ := rc4.NewCipher(rc4Key)
	return &Client{server: s, key: key, localSession: randomByte(), remoteSession: connect.SessionID,
		remoteSig: bytes.Clone(connect.ConnectionSignature), minor: connect.MinorVersion,
		pid: login.pid, cid: login.cid, sessionKey: login.sessionKey,
		connectPacket: bytes.Clone(connect.Payload), connectResponse: login.response,
		queue: make(chan []byte, queueSize), closed: make(chan struct{}),
		encrypt: encrypt, decrypt: decrypt, nextID: 1, expected: 2, // the CONNECT used id 1
		window: map[uint16]*Packet{}, unacked: map[pendingKey]*pending{},
		lastSeen: now, nextPing: now.Add(pingInterval)}
}

func (c *Client) sameConnect(packet *Packet) bool {
	return bytes.Equal(c.connectPacket, packet.Payload)
}

// PID is the authenticated player, 0 on the auth stream.
func (c *Client) PID() uint32 { return c.pid }

// CID is the connection id the player chose at login.
func (c *Client) CID() uint32 { return c.cid }

// MinorVersion is the negotiated PRUDP minor version.
func (c *Client) MinorVersion() uint8 { return c.minor }

// RemoteAddr is where the packets come from.
func (c *Client) RemoteAddr() netip.AddrPort { return c.key.addr }

// Recv returns the next message; false once the connection is over and nothing is left.
func (c *Client) Recv() ([]byte, bool) {
	select {
	case message := <-c.queue:
		return message, true
	default:
	}
	select {
	case message := <-c.queue:
		return message, true
	case <-c.closed:
		select {
		case message := <-c.queue:
			return message, true
		default:
			return nil, false
		}
	}
}

// Done is closed when the connection is over.
func (c *Client) Done() <-chan struct{} { return c.closed }

// Send delivers a message reliably, in fragments.
func (c *Client) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disconnected || c.disconnecting {
		return errors.New("the connection is closed")
	}
	fragment := uint8(1)
	for len(data) > 0 {
		chunk := data
		if len(chunk) <= fragmentSize {
			fragment = 0
		} else {
			chunk = data[:fragmentSize]
		}
		encrypted := make([]byte, len(chunk))
		c.encrypt.XORKeyStream(encrypted, chunk)
		c.sendReliable(&Packet{Type: TypeData, Flags: FlagReliable | FlagNeedAck | FlagHasSize,
			FragmentID: fragment, Payload: encrypted})
		data = data[len(chunk):]
		if fragment++; fragment == 0 { // 0 ends a message
			fragment = 1
		}
	}
	return nil
}

func (c *Client) address(packet *Packet) {
	packet.SourcePort, packet.SourceType = vPort, streamType
	packet.DestPort, packet.DestType = c.key.port, c.key.kind
	packet.SessionID = c.localSession
	packet.Signature = c.server.signer.Sign(packet, c.sessionKey, c.remoteSig)
}

func (c *Client) sendReliable(packet *Packet) {
	packet.PacketID = c.nextID
	c.nextID++
	c.address(packet)
	data := packet.Encode()
	c.unacked[pendingKey{packet.Type, packet.PacketID}] = &pending{data: data, next: time.Now().Add(resendTimeout)}
	_, _ = c.server.conn.WriteToUDPAddrPort(data, c.key.addr)
}

func (c *Client) sendPlain(packet *Packet) {
	c.address(packet)
	_, _ = c.server.conn.WriteToUDPAddrPort(packet.Encode(), c.key.addr)
}

// Close ends the connection at once (three unreliable DISCONNECTs, in case some get lost).
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disconnected {
		return
	}
	for i := 0; i < 3; i++ {
		c.sendPlain(&Packet{Type: TypeDisconnect})
	}
	c.cleanup()
}

// disconnect ends the connection gracefully once the handler is finished.
func (c *Client) disconnect() {
	c.mu.Lock()
	if c.disconnected {
		c.mu.Unlock()
		return
	}
	c.disconnecting = true
	c.gaveUpAt = time.Now().Add(disconnectTimeout)
	c.sendReliable(&Packet{Type: TypeDisconnect, Flags: FlagReliable | FlagNeedAck})
	c.mu.Unlock()
	<-c.closed
}

func (c *Client) cleanup() {
	if c.disconnected {
		return
	}
	c.disconnected = true
	c.unacked = nil
	close(c.closed)
}

func (c *Client) tick(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disconnected {
		return
	}
	if c.disconnecting && now.After(c.gaveUpAt) {
		c.cleanup()
		return
	}
	idle := c.server.options.IdleTimeout
	if idle > 0 && now.Sub(c.lastSeen) > idle {
		logx.Warnf("closing idle connection %s (no packet for %.0fs)", c.key.addr, now.Sub(c.lastSeen).Seconds())
		c.cleanup()
		return
	}
	if !c.disconnecting && now.After(c.nextPing) {
		c.nextPing = now.Add(pingInterval)
		c.sendReliable(&Packet{Type: TypePing, Flags: FlagReliable | FlagNeedAck})
	}
	for _, entry := range c.unacked {
		if now.Before(entry.next) {
			continue
		}
		if entry.resent >= resendLimit {
			logx.Warnf("connection %s lost: a packet timed out", c.key.addr)
			c.cleanup()
			return
		}
		entry.resent++
		entry.next = now.Add(resendTimeout)
		_, _ = c.server.conn.WriteToUDPAddrPort(entry.data, c.key.addr)
	}
}

func (c *Client) handle(packet *Packet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disconnected {
		return nil
	}
	expected := c.server.connectionSignature(c.key.addr)
	if !hmac.Equal(packet.Signature, c.server.signer.Sign(packet, c.sessionKey, expected)) {
		return errors.New("invalid signature")
	}
	c.lastSeen = time.Now() // only a real packet counts as life: a forged one proves nothing
	if packet.Flags&FlagMultiAck != 0 {
		return c.handleAggregateAck(packet)
	}
	if packet.SubstreamID != 0 {
		return errors.New("invalid substream")
	}
	if packet.SessionID != c.remoteSession {
		return errors.New("invalid session id")
	}
	if packet.Flags&FlagAck != 0 {
		delete(c.unacked, pendingKey{packet.Type, packet.PacketID})
		if packet.Type == TypeDisconnect {
			c.cleanup()
		}
		return nil
	}
	if packet.Flags&FlagReliable != 0 && int16(packet.PacketID-c.expected) >= windowSize {
		return errors.New("packet beyond the window") // not acked: it will come back
	}
	if packet.Flags&FlagNeedAck != 0 {
		c.sendAck(packet)
	}
	if packet.Flags&FlagReliable != 0 {
		c.processReliable(packet)
	} else if packet.Type == TypeDisconnect {
		c.cleanup()
	}
	return nil
}

func (c *Client) sendAck(packet *Packet) {
	ack := &Packet{Type: packet.Type, Flags: FlagAck, PacketID: packet.PacketID,
		FragmentID: packet.FragmentID, SubstreamID: packet.SubstreamID}
	count := 1
	if packet.Type == TypeDisconnect {
		count = 3
	}
	for i := 0; i < count; i++ {
		c.sendPlain(ack)
	}
}

func (c *Client) processReliable(packet *Packet) {
	if int16(packet.PacketID-c.expected) < 0 || c.window[packet.PacketID] != nil {
		return // a duplicate
	}
	copied := *packet
	copied.Payload = bytes.Clone(packet.Payload) // the datagram buffer is reused
	c.window[packet.PacketID] = &copied
	for {
		next := c.window[c.expected]
		if next == nil {
			return
		}
		delete(c.window, c.expected)
		c.expected++
		switch next.Type {
		case TypeData:
			if !c.deliver(next) {
				return
			}
		case TypeDisconnect:
			c.cleanup()
			return
		}
	}
}

func (c *Client) deliver(packet *Packet) bool {
	clear := make([]byte, len(packet.Payload))
	c.decrypt.XORKeyStream(clear, packet.Payload)
	c.fragments = append(c.fragments, clear...)
	if len(c.fragments) > maxMessage {
		logx.Warnf("connection %s closed: message too large", c.key.addr)
		c.cleanup()
		return false
	}
	if packet.FragmentID != 0 {
		return true
	}
	message := c.fragments
	c.fragments = nil
	select {
	case c.queue <- message:
		return true
	default: // the handler is far behind: a flood, not a player
		logx.Warnf("connection %s closed: too many requests waiting", c.key.addr)
		c.cleanup()
		return false
	}
}

func (c *Client) handleAggregateAck(packet *Packet) error {
	payload := packet.Payload
	if packet.Type != TypeData || len(payload)%2 != 0 || packet.SubstreamID > 1 {
		return errors.New("invalid aggregate ack")
	}
	var (
		substream uint8
		base      uint16
		extras    []byte
	)
	if packet.SubstreamID == 1 { // the newer form
		if len(payload) < 4 || len(payload) != 4+int(payload[1])*2 {
			return errors.New("invalid aggregate ack")
		}
		substream, base, extras = payload[0], binary.LittleEndian.Uint16(payload[2:]), payload[4:]
	} else {
		if len(payload) < 4 {
			return errors.New("invalid aggregate ack")
		}
		base, extras = packet.PacketID, payload
	}
	if substream != 0 {
		return nil
	}
	for key := range c.unacked {
		if key.kind == TypeData && int16(key.id-base) <= 0 {
			delete(c.unacked, key)
		}
	}
	for ; len(extras) >= 2; extras = extras[2:] {
		delete(c.unacked, pendingKey{TypeData, binary.LittleEndian.Uint16(extras)})
	}
	return nil
}
