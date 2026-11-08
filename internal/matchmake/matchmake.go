// Package matchmake holds the live state of the game server: who is connected, where peers can
// reach them, and the matchmaking sessions. Sessions live in memory only.
//
// Lab mode keeps its same-PC shortcuts and leaves sessions open until a client closes them. Public
// mode adds the classic-match fill: at most 8 players, and the session closes when full or when its
// fill window ends, so a match starts with whoever came. Private rooms are never closed by the server.
package matchmake

import (
	"crypto/rand"
	"encoding/binary"
	"slices"
	"sync"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
	"github.com/lgicbd/SplatPc-Server/internal/station"
)

const (
	defaultFillTimeout = 20 * time.Second
	maxPlayers         = 8
	maxSessionsPerPID  = 3 // public: one account cannot fill the table
	maxSessions        = 512
	sessionTTL         = 600 * time.Second // a closed session is forgotten after this long
	maxJoinMessage     = 200               // join messages are rebroadcast to every member
	notifyDelay        = 200 * time.Millisecond

	participationJoin = 3001
	firstGID          = 0x1000
	maxGID            = 0x7FFFFFFF
	firstConnectionID = 0x1000
	sessionKeySize    = 32

	protocolNotification = 14
	methodNotification   = 1
)

// NATObservations gives the peer-to-peer port the NAT check saw from an address.
type NATObservations interface {
	Consume(host string) (port int, found bool)
}

// Options configure a Matchmaker.
type Options struct {
	Public           bool
	FillTimeout      float64 // seconds, 0 for the default
	RandomSessionKey bool
	LANPublic        string // public address for players on the server's own LAN
	NAT              NATObservations
}

type endpoint struct {
	host string
	port int
}

// Matchmaker is the state of one server run. One mutex guards it all: nothing inside blocks.
type Matchmaker struct {
	options     Options
	fillTimeout time.Duration

	mu           sync.Mutex
	stopped      bool
	nextGID      uint32
	order        []uint32 // creation order: the oldest open session fills first
	sessions     map[uint32]*Session
	members      map[uint32][]uint32 // owner first
	deadlines    map[uint32]time.Time
	timers       map[uint32]*time.Timer
	closedAt     map[uint32]time.Time
	stations     map[uint32][]*station.URL
	clients      map[uint32]*rmc.Conn
	live         map[uint32]map[*rmc.Conn]bool
	peers        map[uint32]endpoint
	natPorts     map[uint32]int
	byRVCID      map[uint32]uint32
	fakeIPs      map[string]bool
	publicIPs    map[uint32]string
	connectionID uint32
}

// New prepares an empty server state.
func New(options Options) *Matchmaker {
	fill := defaultFillTimeout
	if options.FillTimeout > 0 {
		fill = time.Duration(options.FillTimeout * float64(time.Second))
	}
	return &Matchmaker{options: options, fillTimeout: fill, nextGID: firstGID,
		sessions: map[uint32]*Session{}, members: map[uint32][]uint32{},
		deadlines: map[uint32]time.Time{}, timers: map[uint32]*time.Timer{}, closedAt: map[uint32]time.Time{},
		stations: map[uint32][]*station.URL{}, clients: map[uint32]*rmc.Conn{},
		live: map[uint32]map[*rmc.Conn]bool{}, peers: map[uint32]endpoint{}, natPorts: map[uint32]int{},
		byRVCID: map[uint32]uint32{}, fakeIPs: map[string]bool{}, publicIPs: map[uint32]string{},
		connectionID: firstConnectionID}
}

func capacity(s *Session) int {
	wanted := int(s.MaxParticipants)
	if wanted == 0 {
		wanted = maxPlayers
	}
	return max(1, min(wanted, maxPlayers))
}

func (m *Matchmaker) isFull(s *Session) bool { return len(m.members[s.ID]) >= capacity(s) }

func (m *Matchmaker) expired(s *Session, at time.Time) bool {
	deadline, found := m.deadlines[s.ID]
	return found && !at.Before(deadline)
}

func (m *Matchmaker) purge(at time.Time) {
	for gid, closed := range m.closedAt {
		if at.Sub(closed) >= sessionTTL {
			m.forget(gid)
		}
	}
}

func (m *Matchmaker) forget(gid uint32) {
	if timer := m.timers[gid]; timer != nil {
		timer.Stop()
	}
	delete(m.timers, gid)
	delete(m.deadlines, gid)
	delete(m.closedAt, gid)
	delete(m.sessions, gid)
	delete(m.members, gid)
	if i := slices.Index(m.order, gid); i >= 0 {
		m.order = slices.Delete(m.order, i, i+1)
	}
}

func (m *Matchmaker) findOpen(wanted *Session) *Session {
	at := time.Now()
	m.purge(at)
	for _, gid := range slices.Clone(m.order) {
		s := m.sessions[gid]
		if !s.Open || s.GameMode != wanted.GameMode {
			continue
		}
		if m.isFull(s) {
			m.close(s, "full")
			continue
		}
		if m.expired(s, at) {
			m.close(s, "fill window over")
			continue
		}
		return s
	}
	return nil
}

func randomUint32() uint32 {
	var buffer [4]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint32(buffer[:])
}

func (m *Matchmaker) newGID() uint32 {
	if !m.options.Public {
		m.nextGID++
		return m.nextGID
	}
	// Unpredictable ids: a stranger cannot walk through 0x1001, 0x1002...
	for {
		gid := firstGID + randomUint32()%(maxGID-firstGID)
		if m.sessions[gid] == nil {
			return gid
		}
	}
}

func (m *Matchmaker) create(s *Session, pid uint32, fillWindow time.Duration) (*Session, error) {
	m.purge(time.Now())
	if len(m.sessions) >= maxSessions {
		logx.Warnf("  matchmaking refused: %d sessions already open", len(m.sessions))
		return nil, rmc.Refuse(rmc.SessionFull)
	}
	if m.options.Public {
		owned := 0
		for _, other := range m.sessions {
			if other.Owner == pid {
				owned++
			}
		}
		if owned >= maxSessionsPerPID {
			logx.Warnf("  matchmaking refused: pid %08x already owns %d sessions", pid, maxSessionsPerPID)
			return nil, rmc.Refuse(rmc.SessionFull)
		}
	}
	s.ID = m.newGID()
	s.Owner, s.Host = pid, pid
	s.Started = now()
	s.SessionKey = make([]byte, sessionKeySize)
	if m.options.RandomSessionKey {
		if _, err := rand.Read(s.SessionKey); err != nil {
			panic(err)
		}
	}
	m.sessions[s.ID] = s
	m.members[s.ID] = nil
	m.order = append(m.order, s.ID)
	if fillWindow > 0 {
		m.deadlines[s.ID] = time.Now().Add(fillWindow)
	}
	return s, nil
}

func (m *Matchmaker) close(s *Session, why string) {
	if timer := m.timers[s.ID]; timer != nil {
		timer.Stop()
		delete(m.timers, s.ID)
	}
	if s.Open {
		s.Open = false
		m.closedAt[s.ID] = time.Now()
		logx.Infof("  matchmaking closed gid=%08x (%s) with %d player(s)", s.ID, why, len(m.members[s.ID]))
	}
}

// armStartTimer closes a public session when its fill window ends, even below 8 players.
func (m *Matchmaker) armStartTimer(s *Session) {
	deadline, found := m.deadlines[s.ID]
	if !m.options.Public || !found || m.timers[s.ID] != nil {
		return
	}
	m.timers[s.ID] = time.AfterFunc(time.Until(deadline), func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.sessions[s.ID] == s && s.Open {
			m.close(s, "fill window over")
		}
	})
}

// checkJoinable refuses, in public mode, a stranger on a closed or full session.
func (m *Matchmaker) checkJoinable(s *Session, pid uint32) error {
	if !m.options.Public || m.isMember(s, pid) {
		return nil
	}
	if !s.Open {
		logx.Warnf("  join refused: gid=%08x is closed (caller %08x)", s.ID, pid)
		return rmc.Refuse(rmc.SessionClosed)
	}
	if m.isFull(s) {
		logx.Warnf("  join refused: gid=%08x is full (caller %08x)", s.ID, pid)
		return rmc.Refuse(rmc.SessionFull)
	}
	return nil
}

func (m *Matchmaker) join(s *Session, pid uint32, claimed int) {
	if !m.isMember(s, pid) {
		m.members[s.ID] = append(m.members[s.ID], pid)
	}
	// Never trust the count the client claims: it is shown to every member.
	s.NumParticipants = uint32(min(max(len(m.members[s.ID]), claimed), capacity(s)))
}

func (m *Matchmaker) leave(gid, pid uint32) bool {
	members, found := m.members[gid]
	if !found {
		return false
	}
	if i := slices.Index(members, pid); i >= 0 {
		members = slices.Delete(members, i, i+1)
		m.members[gid] = members
	}
	if len(members) == 0 {
		m.forget(gid)
	} else if s := m.sessions[gid]; s.Owner == pid {
		s.Owner, s.Host = members[0], members[0]
	}
	return true
}

func (m *Matchmaker) get(gid uint32) (*Session, error) {
	if s := m.sessions[gid]; s != nil {
		return s, nil
	}
	return nil, rmc.Refuse(rmc.SessionVoid)
}

func (m *Matchmaker) isMember(s *Session, pid uint32) bool {
	return slices.Contains(m.members[s.ID], pid)
}

// allowHost is true for the owner; anyone else is refused quietly.
func (m *Matchmaker) allowHost(s *Session, pid uint32, action string) bool {
	if s.Owner == pid {
		return true
	}
	logx.Warnf("  %s from %08x refused: %08x owns gid=%08x", action, pid, s.Owner, s.ID)
	return false
}

// notifyJoin tells every participant, the newcomer included, that someone joined. It waits a moment:
// the game must first see the answer it is waiting on.
func (m *Matchmaker) notifyJoin(s *Session, pid uint32, message string) {
	text := []rune(message)
	if len(text) > maxJoinMessage {
		text = text[:maxJoinMessage]
	}
	members := slices.Clone(m.members[s.ID])
	joined := event{pid: pid, kind: participationJoin, param1: s.ID, param2: pid,
		text: string(text), param3: uint32(len(members))}
	time.AfterFunc(notifyDelay, func() {
		for _, member := range members {
			m.mu.Lock()
			client, stopped := m.clients[member], m.stopped
			m.mu.Unlock()
			if client == nil || stopped {
				continue
			}
			if err := client.Request(protocolNotification, methodNotification, joined.encode); err != nil {
				logx.Warnf("  notification to %08x failed: %v", member, err)
				continue
			}
			logx.Infof("  notified %08x: type=%d gid=%08x joined=%08x", member, joined.kind, joined.param1, joined.param2)
		}
	})
}

// ConnectionOpened counts a player's connection; a player opens several.
func (m *Matchmaker) ConnectionOpened(conn *rmc.Conn) {
	pid := conn.PID()
	if pid == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live[pid] == nil {
		m.live[pid] = map[*rmc.Conn]bool{}
	}
	m.live[pid][conn] = true
}

// ConnectionClosed drops every trace of the player when its last connection is gone. A connection
// a newer Register has replaced does not count: closing it late must not erase the new session.
func (m *Matchmaker) ConnectionClosed(conn *rmc.Conn) {
	pid := conn.PID()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.live[pid][conn] {
		return
	}
	delete(m.live[pid], conn)
	if len(m.live[pid]) == 0 {
		delete(m.live, pid)
		m.forgetPlayer(pid)
	}
}

func (m *Matchmaker) forgetAddresses(pid uint32) {
	delete(m.clients, pid)
	delete(m.stations, pid)
	delete(m.peers, pid)
	for id, owner := range m.byRVCID {
		if owner == pid {
			delete(m.byRVCID, id)
		}
	}
}

func (m *Matchmaker) forgetPlayer(pid uint32) {
	m.forgetAddresses(pid)
	for _, gid := range slices.Clone(m.order) {
		s := m.sessions[gid]
		if !m.isMember(s, pid) {
			continue
		}
		members := m.members[gid]
		members = slices.Delete(members, slices.Index(members, pid), slices.Index(members, pid)+1)
		m.members[gid] = members
		switch {
		case s.Host == pid:
			m.close(s, "host disconnected")
			m.forget(gid)
		case len(members) == 0:
			m.close(s, "empty")
			m.forget(gid)
		default:
			s.NumParticipants = uint32(len(members))
		}
	}
}

// SessionInfo describes a session to the operators.
type SessionInfo struct {
	ID, Host uint32
	Members  int
	Closed   bool
}

// Stats counts the players with a live connection, the sessions not yet closed, and the connections.
func (m *Matchmaker) Stats() (players, sessions, connections int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, conns := range m.live {
		connections += len(conns)
	}
	return len(m.clients), len(m.sessions) - len(m.closedAt), connections
}

// Sessions lists every session, closed ones included until they are forgotten.
func (m *Matchmaker) Sessions() []SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := make([]SessionInfo, 0, len(m.order))
	for _, gid := range m.order {
		_, closed := m.closedAt[gid]
		list = append(list, SessionInfo{gid, m.sessions[gid].Host, len(m.members[gid]), closed})
	}
	return list
}

// ActivePlayers lists the connected players.
func (m *Matchmaker) ActivePlayers() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := make([]uint32, 0, len(m.clients))
	for pid := range m.clients {
		list = append(list, pid)
	}
	slices.Sort(list)
	return list
}

// Kick disconnects a player at once and forgets it.
func (m *Matchmaker) Kick(pid uint32) {
	m.mu.Lock()
	client := m.clients[pid]
	delete(m.live, pid)
	m.forgetPlayer(pid)
	m.mu.Unlock()
	if client != nil {
		client.Close()
	}
	logx.Warnf("player %08x kicked by operator", pid)
}

// Stop closes every session and cancels the timers.
func (m *Matchmaker) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
	for _, gid := range slices.Clone(m.order) {
		m.close(m.sessions[gid], "server shutdown")
		m.forget(gid)
	}
}
