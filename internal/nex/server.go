// Package nex assembles the game-facing servers: authentication and secure, on two PRUDP streams.
package nex

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/config"
	"github.com/lgicbd/SplatPc-Server/internal/kerberos"
	"github.com/lgicbd/SplatPc-Server/internal/limit"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/matchmake"
	"github.com/lgicbd/SplatPc-Server/internal/prudp"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
)

const (
	// AccessKey is the game's PRUDP access key.
	AccessKey = "6f599f81"

	secureKeySize    = 16
	maxConnections   = 1024
	maxConnectionsIP = 32
	refusalLogPeriod = 10 * time.Second
	maxRefusalHosts  = 4096
)

// Options are what the servers need beyond the configuration.
type Options struct {
	Config       *config.Config
	Accounts     *accounts.Store
	Attested     func(uint32) bool
	Matchmaker   *matchmake.Matchmaker
	AdvertiseLAN string // address for players on the server's own LAN
	IdleTimeout  time.Duration
}

// Server is the pair of running streams.
type Server struct {
	options Options
	limiter *connectionLimiter
	auth    *prudp.Server
	secure  *prudp.Server
}

// Start binds both streams.
func Start(options Options) (*Server, error) {
	cfg := options.Config
	secureKey := kerberos.RandomBytes(secureKeySize)
	s := &Server{options: options, limiter: newConnectionLimiter(maxConnections, maxConnectionsIP)}
	host := cfg.StationHost()
	station := fmt.Sprintf("prudps:/address=%s;port=%d;CID=1;PID=%d;sid=1;stream=10;type=2", host, cfg.SecurePort, securePID)
	identityRoots := DefaultIdentityRoots
	if cfg.HasIdentityRoots {
		identityRoots = cfg.IdentityRoots
	}
	authService := &auth{public: cfg.IsPublic(), secureKey: secureKey, station: station,
		accounts: options.Accounts, attested: options.Attested,
		identities: cfg.Identities, roots: identityRoots,
		ipRate: limit.New(maxLoginsPerIP, rateWindow, nil), pidRate: limit.New(maxTicketsPerPID, rateWindow, nil)}
	if options.AdvertiseLAN != "" {
		authService.lanStation = strings.Replace(station, "address="+host+";", "address="+options.AdvertiseLAN+";", 1)
	}
	var err error
	s.auth, err = prudp.Listen(cfg.Listen, cfg.AuthPort, prudp.Options{AccessKey: AccessKey, IdleTimeout: options.IdleTimeout,
		Handler: s.handler(rmc.Services{protocolAuth: authService.methods()})})
	if err != nil {
		return nil, fmt.Errorf("auth port %d: %w", cfg.AuthPort, err)
	}
	s.secure, err = prudp.Listen(cfg.Listen, cfg.SecurePort, prudp.Options{AccessKey: AccessKey, SecureKey: secureKey,
		IdleTimeout: options.IdleTimeout, Handler: s.handler(options.Matchmaker.Services())})
	if err != nil {
		s.auth.Close()
		return nil, fmt.Errorf("secure port %d: %w", cfg.SecurePort, err)
	}
	logx.Infof("mode=%s auth %s:%d, secure %s:%d, advertise %s", cfg.Mode, cfg.Listen, cfg.AuthPort, cfg.Listen, cfg.SecurePort, host)
	return s, nil
}

// Close ends every connection.
func (s *Server) Close() {
	s.secure.Close()
	s.auth.Close()
}

func (s *Server) handler(services rmc.Services) func(*prudp.Client) {
	return func(client *prudp.Client) {
		ip := client.RemoteAddr().Addr().String()
		if !s.limiter.enter(ip) {
			if s.limiter.shouldLogRefusal(ip) {
				logx.Warnf("connection from %s refused: too many connections", ip)
			}
			client.Close()
			return
		}
		defer s.limiter.leave(ip)
		conn := rmc.NewConn(client, services)
		s.options.Matchmaker.ConnectionOpened(conn)
		defer s.options.Matchmaker.ConnectionClosed(conn)
		if pid := client.PID(); pid != 0 && s.options.Accounts != nil {
			if err := s.options.Accounts.Touch(pid); err != nil {
				logx.Warnf("last seen of %08x: %v", pid, err)
			}
		}
		conn.Run()
	}
}

// connectionLimiter bounds the live connections: a flood must not cost one goroutine per datagram.
type connectionLimiter struct {
	maxTotal, maxPerIP int
	now                func() time.Time
	mu                 sync.Mutex
	total              int
	perIP              map[string]int
	refusals           map[string]time.Time
}

func newConnectionLimiter(maxTotal, maxPerIP int) *connectionLimiter {
	return &connectionLimiter{maxTotal: maxTotal, maxPerIP: maxPerIP, now: time.Now,
		perIP: map[string]int{}, refusals: map[string]time.Time{}}
}

func (l *connectionLimiter) enter(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.perIP[ip] >= l.maxPerIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

func (l *connectionLimiter) leave(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}

func (l *connectionLimiter) shouldLogRefusal(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if last, found := l.refusals[ip]; found && now.Sub(last) < refusalLogPeriod {
		return false
	}
	if len(l.refusals) >= maxRefusalHosts {
		clear(l.refusals)
	}
	l.refusals[ip] = now
	return true
}
