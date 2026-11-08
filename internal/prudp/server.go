package prudp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/kerberos"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
	"github.com/lgicbd/SplatPc-Server/internal/udpsock"
)

const (
	vPort         = 1
	streamType    = 10
	serverMinor   = 4
	maxDatagram   = 2048
	ticketMaxAge  = 120 * time.Second
	janitorPeriod = 100 * time.Millisecond
)

// connectionKey signs the handshake's connection signature, as in NintendoClients.
var connectionKey = []byte{0x26, 0xc3, 0x1f, 0x38, 0x1e, 0x46, 0xd6, 0xeb, 0x38, 0xe1, 0xaf, 0x6a, 0xb7, 0x0d, 0x11}

// Options configure a Server.
type Options struct {
	AccessKey   string
	SecureKey   []byte        // nil: the auth stream, no login request on CONNECT
	IdleTimeout time.Duration // a client silent this long is closed
	Handler     func(*Client) // runs once per connection, on its own goroutine
}

// Timings of reliable delivery. A home link can lose several datagrams in a row: 1.5 s x 10 resends
// tolerates about 16 s of loss before the connection is closed.
const (
	resendTimeout     = 1500 * time.Millisecond
	resendLimit       = 10
	pingInterval      = 5 * time.Second
	disconnectTimeout = 5 * time.Second
)

type clientKey struct {
	addr netip.AddrPort
	port uint8
	kind uint8
}

// Server is one PRUDP stream on one UDP socket.
type Server struct {
	options Options
	signer  *Signer
	conn    *net.UDPConn
	mu      sync.Mutex
	clients map[clientKey]*Client
	done    chan struct{}
	wait    sync.WaitGroup
}

// Listen binds the socket and starts serving.
func Listen(host string, port int, options Options) (*Server, error) {
	conn, err := udpsock.Listen(host, port)
	if err != nil {
		return nil, err
	}
	s := &Server{options: options, signer: NewSigner(options.AccessKey), conn: conn,
		clients: map[clientKey]*Client{}, done: make(chan struct{})}
	s.wait.Add(2)
	go s.readLoop()
	go s.janitor()
	return s, nil
}

// Port is the bound port.
func (s *Server) Port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

// Close stops the server and ends every connection.
func (s *Server) Close() {
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	s.mu.Lock()
	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.Unlock()
	for _, client := range clients {
		client.Close()
	}
	s.conn.Close()
	s.wait.Wait()
}

func (s *Server) readLoop() {
	defer s.wait.Done()
	buffer := make([]byte, maxDatagram)
	for {
		size, addr, err := s.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // a lost peer on Windows, for instance: other players must not suffer
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		// Decoded packets point into the buffer, and every use ends before the next read.
		packets, err := Decode(buffer[:size])
		if err != nil {
			logx.Debugf("dropped datagram from %s: %v", addr, err)
			continue
		}
		for _, packet := range packets {
			if err := s.handle(packet, addr); err != nil {
				logx.Debugf("dropped packet from %s: %v", addr, err)
			}
		}
	}
}

func (s *Server) janitor() {
	defer s.wait.Done()
	ticker := time.NewTicker(janitorPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			clients := make([]*Client, 0, len(s.clients))
			for _, client := range s.clients {
				clients = append(clients, client)
			}
			s.mu.Unlock()
			for _, client := range clients {
				client.tick(now)
			}
		}
	}
}

func (s *Server) send(packet *Packet, addr netip.AddrPort) {
	_, _ = s.conn.WriteToUDPAddrPort(packet.Encode(), addr)
}

func (s *Server) connectionSignature(addr netip.AddrPort) []byte {
	ip := addr.Addr().As4()
	digest := hmac.New(md5.New, connectionKey)
	digest.Write(ip[:])
	digest.Write(binary.BigEndian.AppendUint16(nil, addr.Port()))
	return digest.Sum(nil)
}

func (s *Server) handle(packet *Packet, addr netip.AddrPort) error {
	if !addr.Addr().Is4() {
		return errBadPacket
	}
	if packet.DestPort != vPort || packet.DestType != streamType {
		return fmt.Errorf("unknown stream %d/%d", packet.DestPort, packet.DestType)
	}
	acknowledged := packet.Flags&FlagAck != 0
	switch {
	case packet.Type == TypeSyn && !acknowledged:
		return s.processSyn(packet, addr)
	case packet.Type == TypeConnect && !acknowledged:
		return s.processConnect(packet, addr)
	}
	s.mu.Lock()
	client := s.clients[clientKey{addr, packet.SourcePort, packet.SourceType}]
	s.mu.Unlock()
	if client == nil {
		return errors.New("no such connection")
	}
	return client.handle(packet)
}

func (s *Server) processSyn(packet *Packet, addr netip.AddrPort) error {
	if !hmac.Equal(packet.Signature, s.signer.Sign(packet, nil, nil)) {
		return errors.New("bad SYN signature")
	}
	if packet.Flags&FlagNeedAck == 0 || packet.SessionID != 0 || packet.PacketID != 0 || packet.SubstreamID != 0 {
		return errors.New("invalid SYN")
	}
	for _, b := range packet.ConnectionSignature {
		if b != 0 {
			return errors.New("invalid SYN")
		}
	}
	ack := &Packet{Type: TypeSyn, Flags: FlagAck,
		SourcePort: vPort, SourceType: streamType, DestPort: packet.SourcePort, DestType: packet.SourceType,
		ConnectionSignature: s.connectionSignature(addr),
		MaxSubstreamID:      0, // the game's stream 0 only
		MinorVersion:        min(serverMinor, packet.MinorVersion),
		SupportedFunctions:  0, // the game drops a SYN/ACK that grants function bit 0
	}
	ack.Signature = s.signer.Sign(ack, nil, nil)
	s.send(ack, addr)
	return nil
}

func (s *Server) processConnect(packet *Packet, addr netip.AddrPort) error {
	expected := s.connectionSignature(addr)
	if !hmac.Equal(packet.Signature, s.signer.Sign(packet, nil, expected)) {
		return errors.New("bad CONNECT signature")
	}
	if packet.Flags&FlagNeedAck == 0 || packet.PacketID != 1 || packet.SubstreamID != 0 {
		return errors.New("invalid CONNECT")
	}
	if packet.MaxSubstreamID > 0 || packet.MinorVersion > serverMinor || packet.SupportedFunctions != 0 {
		return errors.New("invalid CONNECT negotiation")
	}
	key := clientKey{addr, packet.SourcePort, packet.SourceType}
	s.mu.Lock()
	existing := s.clients[key]
	s.mu.Unlock()
	if existing != nil && existing.remoteSession == packet.SessionID && existing.sameConnect(packet) {
		s.ackConnect(packet, addr, existing.localSession, existing.connectResponse) // the ack was lost
		return nil
	}
	login, err := s.parseLogin(packet.Payload)
	if err != nil {
		return err
	}
	if existing != nil { // the same socket starts over
		existing.Close()
		s.remove(key, existing)
	}
	client := newClient(s, key, packet, login)
	s.mu.Lock()
	s.clients[key] = client
	s.mu.Unlock()
	s.ackConnect(packet, addr, client.localSession, client.connectResponse)
	s.wait.Add(1)
	go s.serveClient(client)
	return nil
}

func (s *Server) ackConnect(packet *Packet, addr netip.AddrPort, session uint8, response []byte) {
	ack := &Packet{Type: TypeConnect, Flags: FlagAck | FlagHasSize,
		SourcePort: vPort, SourceType: streamType, DestPort: packet.SourcePort, DestType: packet.SourceType,
		ConnectionSignature: make([]byte, signatureSize),
		MaxSubstreamID:      packet.MaxSubstreamID,
		SupportedFunctions:  packet.SupportedFunctions,
		MinorVersion:        packet.MinorVersion,
		SessionID:           session,
		PacketID:            1,
		Payload:             response,
	}
	ack.Signature = s.signer.Sign(ack, nil, packet.ConnectionSignature)
	s.send(ack, addr)
}

func (s *Server) serveClient(client *Client) {
	defer s.wait.Done()
	defer s.remove(client.key, client)
	s.options.Handler(client)
	client.disconnect()
}

func (s *Server) remove(key clientKey, client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clients[key] == client {
		delete(s.clients, key)
	}
}

// loginResult is what a secure CONNECT brings: who it is, and its session key.
type loginResult struct {
	pid        uint32
	cid        uint32
	sessionKey []byte
	response   []byte
}

func (s *Server) parseLogin(data []byte) (*loginResult, error) {
	if s.options.SecureKey == nil {
		return &loginResult{}, nil
	}
	in := nexstream.NewReader(data, false)
	ticketData := in.Buffer()
	requestData := in.Buffer()
	if err := in.Err(); err != nil {
		return nil, err
	}
	ticket, err := kerberos.DecryptServerTicket(ticketData, s.options.SecureKey)
	if err != nil {
		return nil, err
	}
	if ticket.Timestamp.Before(time.Now().Add(-ticketMaxAge)) {
		return nil, errors.New("the ticket has expired")
	}
	clear, err := kerberos.Decrypt(ticket.SessionKey, requestData)
	if err != nil {
		return nil, err
	}
	if len(clear) != 12 {
		return nil, errors.New("invalid login request size")
	}
	request := nexstream.NewReader(clear, false)
	pid, cid, check := request.PID(), request.U32(), request.U32()
	if pid != ticket.Source {
		return nil, errors.New("the login pid is not the ticket's")
	}
	out := nexstream.NewWriter(false)
	out.U32(4)
	out.U32(check + 1)
	return &loginResult{pid, cid, ticket.SessionKey, out.Bytes()}, nil
}

func randomByte() uint8 {
	var one [1]byte
	_, _ = rand.Read(one[:])
	return one[0]
}
