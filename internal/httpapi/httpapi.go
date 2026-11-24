// Package httpapi is the small HTTP endpoint of the public server: sign-up (the game cannot
// register by itself), friends, health and the operators' routes. Plain HTTP on purpose: it is
// meant to sit behind a TLS reverse proxy. Bodies are never logged and responses never echo a
// password or a key.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/jsonval"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/social"
	"github.com/lgicbd/SplatPc-Server/internal/wireguard"
)

const (
	maxBody        = 4096
	maxConnections = 8                // concurrent requests
	requestTimeout = 10 * time.Second // a slow client must not hold a slot forever
)

// Stats are public, secret-free counts.
type Stats struct {
	Players     int `json:"players"`
	Sessions    int `json:"sessions"`
	Connections int `json:"connections"`
}

// SessionInfo describes one matchmaking session to the operators.
type SessionInfo struct {
	ID      uint32
	Host    uint32
	Members int
	Closed  bool
}

// Live is what the endpoint needs from the running game server.
type Live interface {
	Stats() Stats
	Errors() uint64
	Sessions() []SessionInfo
	ActivePlayers() []uint32
	RequestKick(pid uint32)
}

// Options configure a Server.
type Options struct {
	Accounts         *accounts.Store
	Social           *social.Social
	Live             Live
	WG               *wireguard.Manager
	Token            string // registration token, "" for none
	AdminToken       string // defaults to Token; without any, the operator routes do not exist
	BehindProxy      bool
	MinClientVersion string
}

// Server serves the endpoint on one listener.
type Server struct {
	Options
	started time.Time
	http    *http.Server
	address net.Addr
}

func New(options Options) *Server {
	if options.AdminToken == "" {
		options.AdminToken = options.Token
	}
	return &Server{Options: options, started: time.Now()}
}

// Start binds and serves in the background.
func (s *Server) Start(host string, port int) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	s.address = listener.Addr()
	s.http = &http.Server{Handler: s, ReadTimeout: requestTimeout, WriteTimeout: requestTimeout,
		MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0)}
	s.http.SetKeepAlivesEnabled(false)
	go func() {
		_ = s.http.Serve(&boundedListener{Listener: listener, slots: make(chan struct{}, maxConnections)})
	}()
	logx.Infof("registration endpoint http://%s/register", listener.Addr())
	return nil
}

// Address is the bound address.
func (s *Server) Address() net.Addr { return s.address }

// Stop closes the listener and every connection.
func (s *Server) Stop() {
	if s.http != nil {
		_ = s.http.Shutdown(context.Background())
		s.http = nil
	}
}

// boundedListener refuses connections beyond its slots instead of queueing them.
type boundedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &slotConn{Conn: connection, release: func() { <-l.slots }}, nil
		default:
			logx.Warnf("registration: %d requests already in flight, connection refused", maxConnections)
			connection.Close()
		}
	}
}

type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func reply(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"error":"internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func replyError(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}

func internalError(w http.ResponseWriter, err error) {
	logx.Errorf("registration: %v", err)
	replyError(w, http.StatusInternalServerError, "internal error")
}

func tokenOK(expected string, r *http.Request, payload map[string]any) bool {
	if expected == "" {
		return true
	}
	given := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if given == "" {
		if value, present := payload["token"]; present {
			given = jsonval.Str(value)
		}
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(expected)) == 1
}

func (s *Server) adminOK(r *http.Request) bool {
	return s.AdminToken != "" && tokenOK(s.AdminToken, r, nil)
}

// clientIP is the player's address. Behind the local proxy (connection from the loopback only) it
// is the last X-Forwarded-For entry, which the proxy itself appends; the endpoint is bound to
// 127.0.0.1 in that mode, so a forged header from outside cannot reach it.
func (s *Server) clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	peerAddr, peerErr := netip.ParseAddr(peer)
	inWG := peerErr == nil && s.WG != nil && s.WG.Config().Subnet.Contains(peerAddr)
	trustedPeer := peerErr == nil && !inWG && (peerAddr.IsLoopback() || peerAddr.IsPrivate())
	if !s.BehindProxy || !trustedPeer {
		return peer
	}
	var last string
	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if part = strings.TrimSpace(part); part != "" {
			last = part
		}
	}
	if address, err := netip.ParseAddr(last); err == nil {
		return address.String()
	}
	return peer
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.get(w, r)
	case http.MethodPost:
		route := r.URL.Path
		switch {
		case strings.HasPrefix(route, "/social/") || route == "/wg/key":
			s.socialRoute(w, r, route)
		case route == "/admin/ban" || route == "/admin/unban":
			s.adminPost(w, r, route)
		case route == "/register":
			s.register(w, r)
		default:
			replyError(w, http.StatusNotFound, "not found")
		}
	default:
		replyError(w, http.StatusNotImplemented, "unsupported method")
	}
}

func hexPID(pid *uint32) any {
	if pid == nil {
		return nil
	}
	return fmt.Sprintf("%08x", *pid)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		payload := map[string]any{"ok": true} // no account count
		if s.MinClientVersion != "" {
			payload["min_client_version"] = s.MinClientVersion
		}
		if s.Social != nil && s.Social.IntegrityMode != "off" {
			// Versions only, no hashes: the launcher warns an outdated player before a refused sign-in.
			payload["integrity_mode"] = s.Social.IntegrityMode
			if latest := s.Social.LatestVersion(); latest != "" {
				payload["latest_version"] = latest
			}
		}
		reply(w, http.StatusOK, payload)
	case "/metrics":
		// Public and secret-free: counts only, never pids or addresses.
		stats := s.Live.Stats()
		reply(w, http.StatusOK, map[string]any{"uptime": int64(time.Since(s.started).Seconds()), "errors": s.Live.Errors(),
			"players": stats.Players, "sessions": stats.Sessions, "connections": stats.Connections})
	case "/admin/sessions", "/admin/kick", "/admin/bans", "/admin/log":
		if !s.adminOK(r) {
			replyError(w, http.StatusUnauthorized, "admin token required")
			return
		}
		s.adminGet(w, r)
	default:
		replyError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) adminGet(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/admin/bans":
		bans, err := s.Accounts.Bans()
		if err != nil {
			internalError(w, err)
			return
		}
		listed := make([]map[string]any, len(bans))
		for i, ban := range bans {
			listed[i] = map[string]any{"pid": hexPID(ban.PID), "ip": ban.IP, "reason": ban.Reason,
				"created": ban.Created, "expires": ban.Expires}
		}
		reply(w, http.StatusOK, map[string]any{"bans": listed})
	case "/admin/log":
		entries, err := s.Accounts.ModLog(100)
		if err != nil {
			internalError(w, err)
			return
		}
		listed := make([]map[string]any, len(entries))
		for i, entry := range entries {
			listed[i] = map[string]any{"at": entry.At, "action": entry.Action, "pid": hexPID(entry.PID),
				"ip": entry.IP, "detail": entry.Detail}
		}
		reply(w, http.StatusOK, map[string]any{"log": listed})
	case "/admin/sessions":
		s.adminSessions(w)
	default: // /admin/kick
		pid, err := accounts.ParsePID(r.URL.Query().Get("pid"))
		if err != nil {
			replyError(w, http.StatusBadRequest, "invalid pid")
			return
		}
		s.Live.RequestKick(pid)
		if err := s.Accounts.LogAction("kick", &pid, "", ""); err != nil {
			logx.Errorf("moderation log: %v", err)
		}
		reply(w, http.StatusOK, map[string]string{"kick": fmt.Sprintf("%08x", pid)})
	}
}

func (s *Server) adminSessions(w http.ResponseWriter) {
	sessions := []map[string]any{}
	players := []string{}
	known := []uint32{}
	for _, session := range s.Live.Sessions() {
		sessions = append(sessions, map[string]any{"id": session.ID, "host": fmt.Sprintf("%08x", session.Host),
			"members": session.Members, "closed": session.Closed})
		known = append(known, session.Host)
	}
	for _, pid := range s.Live.ActivePlayers() {
		players = append(players, fmt.Sprintf("%08x", pid))
		known = append(known, pid)
	}
	names, err := s.Accounts.PseudosFor(known)
	if err != nil {
		internalError(w, err)
		return
	}
	pseudos := map[string]string{}
	for pid, name := range names {
		pseudos[fmt.Sprintf("%08x", pid)] = name
	}
	reply(w, http.StatusOK, map[string]any{"sessions": sessions, "players": players, "pseudos": pseudos})
}

var errBadBody = errors.New("invalid body")

// readJSON reads a bounded JSON object: errBadBody for a bad length, another error for bad JSON.
func readJSON(r *http.Request) (map[string]any, error) {
	if r.ContentLength <= 0 || r.ContentLength > maxBody {
		return nil, errBadBody
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, errors.New("not UTF-8")
	}
	return jsonval.Decode(data)
}

// text is a body field read as text, with a default for an absent key.
func text(payload map[string]any, key, fallback string) string {
	if value, present := payload[key]; present {
		return jsonval.Str(value)
	}
	return fallback
}

func (s *Server) socialRoute(w http.ResponseWriter, r *http.Request, route string) {
	ip := s.clientIP(r)
	payload, err := readJSON(r)
	if errors.Is(err, errBadBody) || s.Social == nil {
		replyError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err != nil {
		replyError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	var result any
	switch route {
	case "/social/session", "/social/pseudo":
		result, err = s.signedIn(route, payload, ip)
	case "/social/lookup":
		result, err = s.Social.Lookup(text(payload, "token", "None"), payload["pseudo"], ip)
	case "/social/presence":
		var friends []social.Friend
		friends, err = s.Social.Heartbeat(text(payload, "token", "None"), payload["mode"], payload["friends"])
		var requests []social.Request
		if err == nil {
			requests, err = s.Social.PendingRequests(text(payload, "token", "None"))
		}
		result = map[string]any{"friends": friends, "requests": requests}
	case "/social/request":
		result, err = s.Social.SendRequest(text(payload, "token", "None"), payload["pid"])
	case "/social/answer":
		err = s.Social.AnswerRequest(text(payload, "token", "None"), payload["pid"], payload["accept"])
		result = map[string]bool{"ok": true}
	case "/social/cancel":
		err = s.Social.CancelRequest(text(payload, "token", "None"), payload["pid"])
		result = map[string]bool{"ok": true}
	case "/social/wg", "/wg/key":
		result, err = s.wgKey(payload, ip)
	default:
		replyError(w, http.StatusNotFound, "not found")
		return
	}
	var refused *social.Error
	switch {
	case err == nil:
		reply(w, http.StatusOK, result)
	case accounts.IsInvalidIdentity(err):
		replyError(w, http.StatusUnauthorized, "unknown player or wrong password")
	case errors.As(err, &refused):
		replyError(w, refused.Status, refused.Message)
	default:
		internalError(w, err)
	}
}

// signedIn serves the two routes that check a password.
func (s *Server) signedIn(route string, payload map[string]any, ip string) (any, error) {
	if !s.Social.AllowAuth(ip) {
		return nil, &social.Error{Status: http.StatusTooManyRequests, Message: "too many attempts, try again later"}
	}
	pid, err := accounts.ParsePID(jsonval.Str(payload["pid"]))
	if err != nil {
		return nil, err
	}
	banned, err := s.Accounts.IsBanned(&pid, ip)
	if err != nil {
		return nil, err
	}
	if banned {
		return nil, &social.Error{Status: http.StatusForbidden, Message: "this player or address is banned"}
	}
	password := text(payload, "password", "")
	if route == "/social/session" {
		token, err := s.Social.OpenSession(pid, password, payload["client"])
		return map[string]string{"token": token}, err
	}
	pseudo, err := s.Social.ClaimPseudo(pid, password, payload["pseudo"])
	return map[string]string{"pseudo": pseudo}, err
}

// adminPost is ban / unban: {pid?, ip?, hours?, reason?}. A pid ban also kicks the player.
func (s *Server) adminPost(w http.ResponseWriter, r *http.Request, route string) {
	if !s.adminOK(r) {
		replyError(w, http.StatusUnauthorized, "admin token required")
		return
	}
	payload, err := readJSON(r)
	if err != nil {
		replyError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	var pid *uint32
	if jsonval.Truthy(payload["pid"]) {
		parsed, err := accounts.ParsePID(jsonval.Str(payload["pid"]))
		if err != nil {
			replyError(w, http.StatusBadRequest, err.Error())
			return
		}
		pid = &parsed
	}
	ip := ""
	if jsonval.Truthy(payload["ip"]) {
		ip = jsonval.Str(payload["ip"])
	}
	if route == "/admin/ban" {
		err = s.ban(pid, ip, payload)
	} else {
		err = s.unban(pid, ip)
	}
	switch {
	case err == nil:
		reply(w, http.StatusOK, map[string]bool{"ok": true})
	case accounts.IsInvalidIdentity(err):
		replyError(w, http.StatusBadRequest, err.Error())
	default:
		internalError(w, err)
	}
}

func (s *Server) ban(pid *uint32, ip string, payload map[string]any) error {
	var hours *float64
	if value := payload["hours"]; value != nil {
		number, valid := jsonval.Float(value)
		if !valid {
			return &accounts.InvalidIdentityError{Message: "hours must be a number"}
		}
		hours = &number
	}
	if err := s.Accounts.AddBan(pid, ip, text(payload, "reason", ""), hours); err != nil {
		return err
	}
	if pid != nil {
		s.Live.RequestKick(*pid)
		if s.Social != nil {
			s.Social.Revoke(*pid)
		}
		if s.WG != nil {
			if peer, wgErr := s.Accounts.GetWGPeer(*pid); wgErr != nil {
				logx.Errorf("wireguard: lookup peer for ban pid %08x: %v", *pid, wgErr)
			} else if peer != nil {
				if wgErr := s.WG.BanPeer(peer.PublicKey, peer.AssignedIP); wgErr != nil {
					logx.Errorf("wireguard: ban peer pid %08x (%s): %v", *pid, peer.AssignedIP, wgErr)
				}
			}
		}
	}
	return nil
}

func (s *Server) unban(pid *uint32, ip string) error {
	if err := s.Accounts.Unban(pid, ip); err != nil {
		return err
	}
	if pid != nil && s.WG != nil {
		if peer, wgErr := s.Accounts.GetWGPeer(*pid); wgErr == nil && peer != nil {
			s.WG.UnbanIP(peer.AssignedIP)
		}
	}
	return nil
}

// wgKey authenticates the player (by session token or pid+password), verifies they are not
// banned, allocates/updates their WireGuard peer IP, and returns the tunnel configuration.
func (s *Server) wgKey(payload map[string]any, ip string) (any, error) {
	if s.WG == nil {
		return nil, &social.Error{Status: http.StatusNotImplemented, Message: "wireguard p2p is not enabled"}
	}
	var pid uint32
	if token := strings.TrimSpace(text(payload, "token", "")); token != "" && token != "None" {
		pid = s.Social.PIDOf(token)
		if pid == 0 {
			return nil, &social.Error{Status: http.StatusUnauthorized, Message: "invalid or expired session token"}
		}
	} else {
		if !s.Social.AllowAuth(ip) {
			return nil, &social.Error{Status: http.StatusTooManyRequests, Message: "too many attempts, try again later"}
		}
		parsed, err := accounts.ParsePID(jsonval.Str(payload["pid"]))
		if err != nil {
			return nil, err
		}
		if !s.Accounts.Verify(parsed, text(payload, "password", "")) {
			return nil, &accounts.InvalidIdentityError{Message: "unknown player or wrong password"}
		}
		pid = parsed
	}

	banned, err := s.Accounts.IsBanned(&pid, ip)
	if err != nil {
		return nil, err
	}
	if banned {
		return nil, &social.Error{Status: http.StatusForbidden, Message: "this player or address is banned"}
	}

	var generatedPriv string
	pubKey := strings.TrimSpace(text(payload, "public_key", ""))
	if pubKey == "" {
		priv, pub, err := wireguard.GenerateKeypair()
		if err != nil {
			return nil, err
		}
		generatedPriv = priv
		pubKey = pub
	} else {
		validated, err := wireguard.ValidatePublicKey(pubKey)
		if err != nil {
			return nil, &social.Error{Status: http.StatusBadRequest, Message: err.Error()}
		}
		pubKey = validated
	}

	cfg := s.WG.Config()
	peer, err := s.Accounts.AssignWGPeer(pid, pubKey, cfg.Subnet, cfg.ServerIP, cfg.NNCS2IP)
	if err != nil {
		if accounts.IsInvalidIdentity(err) {
			return nil, &social.Error{Status: http.StatusConflict, Message: err.Error()}
		}
		return nil, err
	}
	if err := s.WG.AllowPeer(peer.PublicKey, peer.AssignedIP); err != nil {
		return nil, err
	}

	nncs2IP := cfg.NNCS2IP
	if !nncs2IP.IsValid() {
		nncs2IP = cfg.ServerIP
	}
	reply := map[string]any{
		"client_ip":            peer.AssignedIP,
		"subnet":               cfg.Subnet.String(),
		"server_ip":            cfg.ServerIP.String(),
		"nncs2_ip":             nncs2IP.String(),
		"server_public_key":    s.WG.ServerPublicKey(),
		"endpoint":             cfg.Endpoint,
		"allowed_ips":          cfg.Subnet.String(),
		"persistent_keepalive": cfg.Keepalive,
		"mtu":                  cfg.MTU,
	}
	if generatedPriv != "" {
		reply["private_key"] = generatedPriv
	}
	return reply, nil
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	allowed, err := s.Accounts.Allow(ip)
	if err != nil {
		internalError(w, err)
		return
	}
	if !allowed {
		replyError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	payload, err := readJSON(r)
	if errors.Is(err, errBadBody) {
		replyError(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Every other attempt counts, successes included: account creation stays bounded.
	if countErr := s.Accounts.Failure(ip); countErr != nil {
		internalError(w, countErr)
		return
	}
	if err != nil {
		replyError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !tokenOK(s.Token, r, payload) {
		replyError(w, http.StatusUnauthorized, "invalid registration token")
		return
	}
	pid, pidErr := accounts.ParsePID(jsonval.Str(payload["pid"]))
	var banned bool
	if pidErr == nil {
		banned, err = s.Accounts.IsBanned(&pid, ip)
	} else {
		banned, err = s.Accounts.IsBanned(nil, ip)
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if banned {
		replyError(w, http.StatusForbidden, "this player or address is banned")
		return
	}
	if pidErr != nil {
		replyError(w, http.StatusBadRequest, pidErr.Error())
		return
	}
	if pid < 0x10000000 { // the port never makes smaller ones
		replyError(w, http.StatusBadRequest, "pid out of the range the game generates")
		return
	}
	status, err := s.Accounts.Register(pid, text(payload, "password", ""))
	var taken *accounts.AlreadyRegisteredError
	switch {
	case err == nil:
		reply(w, http.StatusOK, map[string]string{"status": status, "pid": fmt.Sprintf("%08x", pid)})
	case accounts.IsInvalidIdentity(err):
		replyError(w, http.StatusBadRequest, err.Error())
	case errors.As(err, &taken):
		replyError(w, http.StatusConflict, err.Error())
	default:
		internalError(w, err)
	}
}
