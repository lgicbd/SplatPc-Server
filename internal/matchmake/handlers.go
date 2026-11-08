package matchmake

import (
	"fmt"
	"strconv"

	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
	"github.com/lgicbd/SplatPc-Server/internal/station"
)

const (
	protocolNAT           = 3
	protocolMatchMaking   = 21
	protocolMatchMakingEx = 50
	protocolExtension     = 109

	methodInitiateProbe = 2
)

// Services is every protocol of the secure server.
func (m *Matchmaker) Services() rmc.Services {
	return rmc.Services{
		protocolSecure: m.secureMethods(),
		protocolExtension: {
			1:  m.closeParticipation,
			2:  m.openParticipation,
			8:  m.modifyAttribute,
			16: getPlayingSession,
			30: m.joinEx,
			34: m.updateProgressScore,
			38: m.createWithParam,
			39: m.joinWithParam,
			40: m.autoMatchmake,
			41: m.findDetail,
		},
		protocolMatchMaking: {
			2:  m.unregisterGathering,
			41: m.getSessionURLs,
		},
		protocolMatchMakingEx: {1: m.endParticipation},
		protocolNAT: {
			3: m.requestProbe,
			4: reportTraversalResult,
			5: m.reportNATProperties,
		},
	}
}

func getPlayingSession(_ *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	in.U32s()
	if err := in.Err(); err != nil {
		return err
	}
	out.U32(0) // no session in progress
	return nil
}

func (m *Matchmaker) autoMatchmake(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	request := decodeAuto(in)
	if err := in.Err(); err != nil {
		return err
	}
	pid := c.PID()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[pid] = c
	s := m.findOpen(request.session)
	if s == nil {
		fill := m.fillTimeout
		if !m.options.Public {
			fill = 0
		}
		created, err := m.create(request.session, pid, fill)
		if err != nil {
			return err
		}
		s = created
	}
	m.join(s, pid, int(request.count))
	logx.Infof("AutoMatchmake pid=%08x -> gid=%08x owner=%08x members=%d", pid, s.ID, s.Owner, len(m.members[s.ID]))
	if m.options.Public {
		if m.isFull(s) {
			m.close(s, "full")
		} else {
			m.armStartTimer(s)
		}
	}
	s.encode(out)
	m.notifyJoin(s, pid, request.message)
	return nil
}

func (m *Matchmaker) createWithParam(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	request := decodeCreate(in)
	if err := in.Err(); err != nil {
		return err
	}
	pid := c.PID()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[pid] = c
	s, err := m.create(request.session, pid, 0)
	if err != nil {
		return err
	}
	m.join(s, pid, int(request.count))
	logx.Infof("CreateMatchmakeSession pid=%08x -> gid=%08x", pid, s.ID)
	s.encode(out)
	m.notifyJoin(s, pid, request.message)
	return nil
}

func (m *Matchmaker) joinWithParam(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	request := decodeJoin(in)
	if err := in.Err(); err != nil {
		return err
	}
	pid := c.PID()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[pid] = c
	s, err := m.get(request.gid)
	if err != nil {
		return err
	}
	if err := m.checkJoinable(s, pid); err != nil {
		return err
	}
	m.join(s, pid, 0)
	logx.Infof("JoinMatchmakeSession pid=%08x gid=%08x members=%d", pid, s.ID, len(m.members[s.ID]))
	s.encode(out)
	m.notifyJoin(s, pid, request.message)
	return nil
}

func (m *Matchmaker) joinEx(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	gid := in.U32()
	message := in.Text()
	in.Bool() // ignore block list
	in.U16()  // participants
	if err := in.Err(); err != nil {
		return err
	}
	pid := c.PID()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[pid] = c
	s, err := m.get(gid)
	if err != nil {
		return err
	}
	if err := m.checkJoinable(s, pid); err != nil {
		return err
	}
	m.join(s, pid, 0)
	m.notifyJoin(s, pid, message)
	out.Buffer(s.SessionKey)
	return nil
}

func (m *Matchmaker) findDetail(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	gid := in.U32()
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(gid)
	if err != nil {
		return err
	}
	// Public: only a member, or somebody who could still join it, may read a session.
	if err := m.checkJoinable(s, c.PID()); err != nil {
		return err
	}
	s.encode(out)
	return nil
}

func (m *Matchmaker) openParticipation(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	gid := in.U32()
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(gid)
	if err != nil {
		return err
	}
	if m.allowHost(s, c.PID(), "OpenParticipation") {
		s.Open = true
	}
	return nil
}

func (m *Matchmaker) closeParticipation(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	gid := in.U32()
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(gid)
	if err != nil {
		return err
	}
	if m.allowHost(s, c.PID(), "CloseParticipation") {
		m.close(s, fmt.Sprintf("CloseParticipation from %08x", c.PID()))
	}
	return nil
}

func (m *Matchmaker) modifyAttribute(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	gid := in.U32()
	attrib := in.U32()
	value := in.U32()
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(gid)
	if err != nil {
		return err
	}
	if m.allowHost(s, c.PID(), "ModifyCurrentGameAttribute") && uint64(attrib) < uint64(len(s.Attribs)) {
		s.Attribs[attrib] = value
	}
	return nil
}

func (m *Matchmaker) updateProgressScore(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	gid := in.U32()
	score := in.U8()
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(gid)
	if err != nil {
		return err
	}
	if !m.isMember(s, c.PID()) {
		logx.Warnf("  UpdateProgressScore from %08x refused: not a member of gid=%08x", c.PID(), gid)
		return nil
	}
	s.ProgressScore = score
	return nil
}

func (m *Matchmaker) getSessionURLs(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	gid := in.U32()
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.get(gid)
	if err != nil {
		return err
	}
	if !m.isMember(s, c.PID()) { // only participants may learn a host's address
		logx.Warnf("  GetSessionURLs from %08x refused: not a member of gid=%08x", c.PID(), gid)
		return rmc.Refuse(rmc.SessionVoid)
	}
	stations := m.stations[s.Host]
	if len(stations) > 2 {
		stations = stations[:2] // PIA accepts 1 or 2
	}
	urls := make([]*station.URL, len(stations))
	for i, url := range stations {
		urls[i] = url.Copy()
	}
	// The registered URLs carry the NEX socket. Once the game calls ReplaceURL the first URL carries
	// the real PIA endpoint; PEER is only the lab fallback for a host that never announced one.
	if peer, found := m.peers[s.Host]; found && !m.options.Public && (len(urls) == 0 || urls[0].Int("type") != urlTypePublic) {
		for _, url := range urls {
			url.Set("address", peer.host)
			url.SetInt("port", peer.port)
		}
	}
	logx.Infof("GetSessionURLs gid=%08x caller=%08x host=%08x -> %v", gid, c.PID(), s.Host, urls)
	writeStations(out, urls)
	return nil
}

func (m *Matchmaker) unregisterGathering(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	gid := in.U32()
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out.Bool(m.leave(gid, c.PID()))
	return nil
}

func (m *Matchmaker) endParticipation(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	gid := in.U32()
	in.Text() // message
	if err := in.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out.Bool(m.leave(gid, c.PID()))
	return nil
}

func (m *Matchmaker) reportNATProperties(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	natm, natf, rtt := in.U32(), in.U32(), in.U32()
	if err := in.Err(); err != nil {
		return err
	}
	pid := c.PID()
	origin := c.RemoteAddr().Addr().String()
	var (
		port  int
		found bool
	)
	if m.options.NAT != nil {
		port, found = m.options.NAT.Consume(origin)
	}
	logx.Infof("ReportNATProperties pid=%08x natm=%d natf=%d rtt=%d origin=%s port=%d", pid, natm, natf, rtt, origin, port)
	if !found {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.options.Public { // the NAT check runs from the PIA socket
		m.peers[pid] = endpoint{origin, port}
		return nil
	}
	// The address stays the source of the player's NEX packets; the port comes from the NAT check,
	// the one its router really maps the PIA socket to. Peers guessing the local port failed to
	// punch through port-changing NATs.
	m.natPorts[pid] = port
	for _, url := range m.stations[pid] {
		if url.Int("type") == urlTypePublic {
			url.SetInt("port", port)
		}
	}
	return nil
}

func reportTraversalResult(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	cid := in.U32()
	result := in.Bool()
	if err := in.Err(); err != nil {
		return err
	}
	logx.Infof("ReportNATTraversalResult pid=%08x cid=%d result=%t", c.PID(), cid, result)
	return nil
}

func (m *Matchmaker) shareSession(a, b uint32) bool {
	for _, gid := range m.order {
		s := m.sessions[gid]
		if m.isMember(s, a) && m.isMember(s, b) {
			return true
		}
	}
	return false
}

// probeAllowed: the address a player asks others to probe must be its own, or the game of a victim
// could be made to send probes to a third party.
func (m *Matchmaker) probeAllowed(c *rmc.Conn, url *station.URL) bool {
	address := url.Get("address")
	if address == "" || address == c.RemoteAddr().Addr().String() {
		return true
	}
	for _, own := range m.stations[c.PID()] {
		if own.Get("address") == address {
			return true
		}
	}
	return false
}

// requestProbe: a joiner asks each target to send NAT probes to it; the server forwards the request.
func (m *Matchmaker) requestProbe(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	targets := readStations(in)
	probe := readStation(in)
	if err := in.Err(); err != nil {
		return err
	}
	pid := c.PID()
	logx.Infof("RequestProbeInitiationExt pid=%08x targets=%v station=%s", pid, targets, probe)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.options.Public && !m.probeAllowed(c, probe) {
		logx.Warnf("  probe request refused: station %s is not an address of %08x", probe, pid)
		return nil
	}
	forwarded := probe.Copy()
	if !m.options.Public && m.fakeIPs[forwarded.Get("address")] {
		forwarded.Set("address", "127.0.0.1") // where the lab's game sockets really are
	}
	text := forwarded.String()
	for _, url := range targets {
		target := m.byRVCID[uint32(url.Int("RVCID"))]
		if target == 0 {
			parsed, _ := strconv.ParseUint(url.Get("PID"), 10, 32)
			target = uint32(parsed)
		}
		if m.options.Public && !m.shareSession(pid, target) {
			logx.Warnf("  probe request refused: %08x and %08x share no session", pid, target)
			continue
		}
		client := m.clients[target]
		if client == nil {
			logx.Warnf("  no connection for target RVCID=%s PID=%s", url.Get("RVCID"), url.Get("PID"))
			continue
		}
		go func() {
			err := client.Request(protocolNAT, methodInitiateProbe, func(out *nexstream.Writer) { out.Text(text) })
			if err != nil {
				logx.Warnf("  InitiateProbe to %08x failed: %v", target, err)
			}
		}()
	}
	return nil
}
