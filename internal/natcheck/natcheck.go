// Package natcheck is the NAT check server (NNCS) the game asks before peer-to-peer.
//
// Messages are 16 bytes of big-endian u32, type first. The reply echoes the type, then the sender's
// port and IP, and the server's own IP. Types 1, 4, 5, 101, 103 answer from the receiving socket;
// 3 and 102 from the same IP on another port; 2 from the other IP on another port.
package natcheck

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/limit"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/udpsock"
)

const (
	messageSize       = 16
	rateLimit         = 100 // probes per window from one source; a real check sends about 20
	rateWindow        = 10.0
	maxObservations   = 16
	maxObservedHosts  = 65536
	observationMaxAge = 120 * time.Second
	maxDatagram       = 2048
)

// Ports the game uses.
var Ports = []int{10025, 10125}

// LabAddresses are nncs1 and nncs2 on the same PC.
var LabAddresses = []string{"127.0.0.1", "127.0.0.2"}

type observation struct {
	port int
	at   time.Time
}

// Server answers NAT checks and remembers where they came from.
type Server struct {
	addresses  []string
	sameSocket bool
	rate       *limit.Limiter
	alternate  map[string]*net.UDPConn
	sockets    []*net.UDPConn
	wait       sync.WaitGroup

	mu           sync.Mutex
	observations map[string][]observation
}

// Start binds what it can: a port that is taken is only a warning.
func Start(addresses []string, ports []int, sameSocket bool) *Server {
	s := &Server{addresses: addresses, sameSocket: sameSocket, rate: limit.New(rateLimit, rateWindow, nil),
		alternate: map[string]*net.UDPConn{}, observations: map[string][]observation{}}
	for _, address := range addresses {
		if conn, err := udpsock.Listen(address, 0); err != nil {
			logx.Warnf("NAT check %s alternate socket unavailable: %v", address, err)
		} else {
			s.alternate[address] = conn
			s.sockets = append(s.sockets, conn)
		}
		for _, port := range ports {
			conn, err := udpsock.Listen(address, port)
			if err != nil {
				logx.Warnf("NAT check %s:%d unavailable: %v", address, port, err)
				continue
			}
			s.sockets = append(s.sockets, conn)
			s.wait.Add(1)
			go s.serve(conn, address)
		}
	}
	logx.Infof("NAT check on %v ports %v", addresses, ports)
	return s
}

// Close stops the sockets.
func (s *Server) Close() {
	for _, conn := range s.sockets {
		conn.Close()
	}
	s.wait.Wait()
}

func (s *Server) serve(conn *net.UDPConn, address string) {
	defer s.wait.Done()
	buffer := make([]byte, maxDatagram)
	for {
		size, sender, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.handle(conn, address, buffer[:size], netip.AddrPortFrom(sender.Addr().Unmap(), sender.Port()))
	}
}

func (s *Server) handle(conn *net.UDPConn, address string, data []byte, sender netip.AddrPort) {
	host := sender.Addr().String()
	if !s.rate.Allow(host) || len(data) < messageSize || !sender.Addr().Is4() {
		return
	}
	kind := binary.BigEndian.Uint32(data)
	var out *net.UDPConn
	origin := address
	switch kind {
	case 1, 4, 5, 101, 103:
		out = conn
	case 3, 102:
		out = s.alternate[address]
		if s.sameSocket {
			out = conn
		}
	case 2:
		other := ""
		for _, candidate := range s.addresses {
			if candidate != address {
				other = candidate
				break
			}
		}
		if other != "" {
			origin = other
			out = s.alternate[other]
		}
		if s.sameSocket {
			out = conn
		}
	default:
		return
	}
	s.observe(host, int(sender.Port())) // only a real NAT check registers a peer-to-peer endpoint
	if out == nil {
		return
	}
	originIP, err := netip.ParseAddr(origin)
	if err != nil || !originIP.Is4() {
		return
	}
	senderBytes, originBytes := sender.Addr().As4(), originIP.As4()
	reply := binary.BigEndian.AppendUint32(nil, kind)
	reply = binary.BigEndian.AppendUint32(reply, uint32(sender.Port()))
	reply = append(reply, senderBytes[:]...)
	reply = append(reply, originBytes[:]...)
	_, _ = out.WriteToUDPAddrPort(reply, sender)
}

func (s *Server) observe(host string, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, known := s.observations[host]
	if !known && len(s.observations) >= maxObservedHosts { // spoofed sources must not grow the table
		for other := range s.observations {
			delete(s.observations, other)
			break
		}
	}
	entries = append(entries, observation{port, time.Now()})
	if len(entries) > maxObservations {
		entries = entries[len(entries)-maxObservations:]
	}
	s.observations[host] = entries
}

// Consume returns the most recent port seen from a host, once. Everything is keyed by the address
// the datagram really came from, so two players checking at once cannot mix up.
func (s *Server) Consume(host string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.observations[host]
	now := time.Now()
	for len(entries) > 0 && now.Sub(entries[len(entries)-1].at) > observationMaxAge {
		entries = entries[:len(entries)-1]
	}
	if len(entries) == 0 {
		delete(s.observations, host)
		return 0, false
	}
	port := entries[len(entries)-1].port
	entries = entries[:len(entries)-1]
	if len(entries) == 0 {
		delete(s.observations, host)
	} else {
		s.observations[host] = entries
	}
	return port, true
}
