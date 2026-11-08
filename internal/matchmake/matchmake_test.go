package matchmake

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
	"github.com/lgicbd/SplatPc-Server/internal/station"
)

type fakeTransport struct {
	pid    uint32
	addr   string
	closed bool
	sent   [][]byte
}

func (f *fakeTransport) Recv() ([]byte, bool)   { return nil, false }
func (f *fakeTransport) Send(data []byte) error { f.sent = append(f.sent, data); return nil }
func (f *fakeTransport) Close()                 { f.closed = true }
func (f *fakeTransport) PID() uint32            { return f.pid }
func (f *fakeTransport) MinorVersion() uint8    { return 4 }
func (f *fakeTransport) RemoteAddr() netip.AddrPort {
	return netip.MustParseAddrPort(f.addr)
}

func connection(m *Matchmaker, pid uint32, addr string) (*rmc.Conn, *fakeTransport) {
	transport := &fakeTransport{pid: pid, addr: addr}
	conn := rmc.NewConn(transport, m.Services())
	m.ConnectionOpened(conn)
	return conn, transport
}

func sessionFor(mode uint32, players uint16) *Session {
	return &Session{GameMode: mode, MaxParticipants: players, Open: true, Param: []byte{0, 0, 0, 0}}
}

func TestCapacityIsAtMostEight(t *testing.T) {
	for wanted, expected := range map[uint16]int{0: 8, 1: 1, 4: 4, 8: 8, 200: 8} {
		if got := capacity(sessionFor(1, wanted)); got != expected {
			t.Fatalf("capacity(%d) = %d", wanted, got)
		}
	}
}

func TestClaimedCountIsNotTrusted(t *testing.T) {
	m := New(Options{})
	s, err := m.create(sessionFor(1, 8), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.join(s, 10, 200)
	if s.NumParticipants != 8 {
		t.Fatalf("count = %d", s.NumParticipants)
	}
	m.join(s, 10, 0)
	if s.NumParticipants != 1 || len(m.members[s.ID]) != 1 {
		t.Fatalf("count = %d, members = %v", s.NumParticipants, m.members[s.ID])
	}
}

func TestLabIDsFollowEachOtherAndPublicIDsDoNot(t *testing.T) {
	lab := New(Options{})
	first, _ := lab.create(sessionFor(1, 8), 1, 0)
	second, _ := lab.create(sessionFor(1, 8), 1, 0)
	if first.ID != firstGID+1 || second.ID != firstGID+2 {
		t.Fatalf("ids %x %x", first.ID, second.ID)
	}
	public := New(Options{Public: true})
	first, _ = public.create(sessionFor(1, 8), 1, 0)
	second, _ = public.create(sessionFor(1, 8), 1, 0)
	if second.ID == first.ID+1 || first.ID < firstGID || first.ID >= maxGID {
		t.Fatalf("ids %x %x", first.ID, second.ID)
	}
}

func TestSessionLimits(t *testing.T) {
	public := New(Options{Public: true})
	for i := 0; i < maxSessionsPerPID; i++ {
		if _, err := public.create(sessionFor(1, 8), 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := public.create(sessionFor(1, 8), 1, 0); err == nil {
		t.Fatal("one player may not own more sessions")
	}
	if _, err := public.create(sessionFor(1, 8), 2, 0); err != nil {
		t.Fatal("the limit is per player")
	}
	lab := New(Options{})
	for i := 0; i < maxSessions; i++ {
		if _, err := lab.create(sessionFor(1, 8), 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := lab.create(sessionFor(1, 8), 1, 0); err == nil {
		t.Fatal("the table is capped")
	}
}

func TestClosedSessionsAreForgottenAfterTheTTL(t *testing.T) {
	m := New(Options{})
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.close(s, "test")
	m.purge(time.Now().Add(sessionTTL - time.Second))
	if m.sessions[s.ID] == nil {
		t.Fatal("forgotten too early")
	}
	m.purge(time.Now().Add(sessionTTL + time.Second))
	if m.sessions[s.ID] != nil || len(m.order) != 0 {
		t.Fatal("still there")
	}
}

func TestFindOpenFillsTheOldestAndSkipsOtherModes(t *testing.T) {
	m := New(Options{})
	other, _ := m.create(sessionFor(2, 8), 1, 0)
	full, _ := m.create(sessionFor(1, 1), 2, 0)
	m.join(full, 2, 0)
	oldest, _ := m.create(sessionFor(1, 8), 3, 0)
	m.create(sessionFor(1, 8), 4, 0)
	if found := m.findOpen(sessionFor(1, 8)); found != oldest {
		t.Fatalf("found %+v", found)
	}
	if full.Open {
		t.Fatal("the full session must be closed on the way")
	}
	if !other.Open {
		t.Fatal("another mode is left alone")
	}
}

func TestFillWindowExpiresInFindOpen(t *testing.T) {
	m := New(Options{Public: true})
	s, _ := m.create(sessionFor(1, 8), 1, time.Nanosecond)
	time.Sleep(time.Millisecond)
	if found := m.findOpen(sessionFor(1, 8)); found != nil {
		t.Fatal("the window is over")
	}
	if s.Open {
		t.Fatal("still open")
	}
}

func TestHostLeavingHandsOverOnLeaveAndEndsOnDisconnect(t *testing.T) {
	m := New(Options{})
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 0)
	m.join(s, 2, 0)
	if !m.leave(s.ID, 1) || s.Owner != 2 || s.Host != 2 {
		t.Fatalf("owner %d host %d", s.Owner, s.Host)
	}
	if m.leave(0x7000, 1) {
		t.Fatal("no such session")
	}
	if !m.leave(s.ID, 2) || m.sessions[s.ID] != nil {
		t.Fatal("an empty session is forgotten")
	}

	s, _ = m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 0)
	m.join(s, 2, 0)
	m.forgetPlayer(2)
	if s.NumParticipants != 1 || m.sessions[s.ID] == nil {
		t.Fatal("a member leaving keeps the session")
	}
	m.join(s, 2, 0)
	m.forgetPlayer(1)
	if m.sessions[s.ID] != nil {
		t.Fatal("the host leaving ends the session")
	}
}

func TestLastConnectionForgetsThePlayer(t *testing.T) {
	m := New(Options{})
	first, _ := connection(m, 1, "1.2.3.4:5")
	second, _ := connection(m, 1, "1.2.3.4:6")
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 0)
	m.ConnectionClosed(first)
	if m.sessions[s.ID] == nil {
		t.Fatal("a service socket closing must not erase the player")
	}
	m.ConnectionClosed(second)
	if m.sessions[s.ID] != nil {
		t.Fatal("the last connection is gone")
	}
}

func TestOldConnectionClosingAfterARegisterKeepsTheNewSession(t *testing.T) {
	m := New(Options{})
	old, _ := connection(m, 1, "1.2.3.4:5")
	fresh, _ := connection(m, 1, "1.2.3.4:6")
	if err := m.register(fresh, nil, nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	m.ConnectionClosed(old) // the cut connection times out long after the player came back
	if m.clients[1] != fresh {
		t.Fatal("the new connection was erased")
	}
	_, _, connections := m.Stats()
	if connections != 1 {
		t.Fatalf("%d connections", connections)
	}
}

func TestLabFallsBackOnThePeerOnlyWithoutAnAnnouncedPIASocket(t *testing.T) {
	m := New(Options{})
	host, _ := connection(m, 1, "127.0.0.1:5")
	guest, _ := connection(m, 2, "127.0.0.1:6")
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 0)
	m.join(s, 2, 0)
	_ = host
	nat, _ := station.Parse("prudp:/address=127.0.0.1;port=40000;type=3")
	m.stations[1] = []*station.URL{nat}
	m.peers[1] = endpoint{"127.0.0.1", 40007}

	urlsOf := func() *station.URL {
		in := nexstream.NewWriter(true)
		in.U32(s.ID)
		out := nexstream.NewWriter(true)
		if err := m.getSessionURLs(guest, nexstream.NewReader(in.Bytes(), true), out); err != nil {
			t.Fatal(err)
		}
		reader := nexstream.NewReader(out.Bytes(), true)
		return readStations(reader)[0]
	}
	if url := urlsOf(); url.Int("port") != 40000 {
		t.Fatalf("announced: %s", url)
	}
	plain, _ := station.Parse("prudp:/address=127.0.0.1;port=1234;type=2")
	m.stations[1] = []*station.URL{plain}
	if url := urlsOf(); url.Int("port") != 40007 {
		t.Fatalf("fallback: %s", url)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	s := &Session{ID: 1, Owner: 2, Host: 3, MinParticipants: 4, MaxParticipants: 5, Policy: 6, PolicyArgument: 7, Flags: 8,
		State: 9, Description: "d", GameMode: 10, Attribs: []uint32{11, 12}, Open: true, MatchmakeSystem: 13,
		ApplicationData: []byte("app"), NumParticipants: 14, ProgressScore: 15, SessionKey: []byte("key"), Option: 16,
		Param: []byte{0, 0, 0, 0}, Started: 17, UserPassword: "p", ReferGID: 18, UserPasswordEnabled: true, SystemPasswordEnabled: true}
	out := nexstream.NewWriter(true)
	s.encode(out)
	in := nexstream.NewReader(out.Bytes(), true)
	got := decodeSession(in)
	if in.Err() != nil || in.Remaining() != 0 {
		t.Fatalf("err=%v remaining=%d", in.Err(), in.Remaining())
	}
	again := nexstream.NewWriter(true)
	got.encode(again)
	if !bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Fatal("not stable")
	}
}

func TestVariantsAreKeptAndUnknownOnesRefused(t *testing.T) {
	body := nexstream.NewWriter(false)
	body.U32(1)
	body.Text("k")
	body.U8(1) // a positive signed integer travels as unsigned
	body.U64(5)
	wrapped := nexstream.NewWriter(true)
	wrapped.U8(0)
	wrapped.Buffer(body.Bytes())
	in := nexstream.NewReader(wrapped.Bytes(), true)
	param := decodeParam(in)
	if in.Err() != nil {
		t.Fatal(in.Err())
	}
	expected := nexstream.NewWriter(false)
	expected.U32(1)
	expected.Text("k")
	expected.U8(6)
	expected.U64(5)
	if !bytes.Equal(param, expected.Bytes()) {
		t.Fatalf("param = %v", param)
	}

	bad := nexstream.NewWriter(true)
	bad.U8(0)
	unknown := nexstream.NewWriter(false)
	unknown.U32(1)
	unknown.Text("k")
	unknown.U8(99)
	bad.Buffer(unknown.Bytes())
	in = nexstream.NewReader(bad.Bytes(), true)
	decodeParam(in)
	if in.Err() == nil {
		t.Fatal("an unknown variant was accepted")
	}
}

func TestKickClosesAndForgets(t *testing.T) {
	m := New(Options{Public: true})
	conn, transport := connection(m, 1, "1.2.3.4:5")
	if err := m.register(conn, nil, nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 0)
	m.Kick(1)
	if !transport.closed || m.sessions[s.ID] != nil || m.clients[1] != nil {
		t.Fatal("the player is still there")
	}
	m.ConnectionClosed(conn) // the handler ending afterwards changes nothing
	if players, sessions, connections := m.Stats(); players+sessions+connections != 0 {
		t.Fatalf("stats %d %d %d", players, sessions, connections)
	}
}
