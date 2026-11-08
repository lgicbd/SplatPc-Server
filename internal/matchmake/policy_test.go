package matchmake

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
	"github.com/lgicbd/SplatPc-Server/internal/station"
)

func params(write func(out *nexstream.Writer)) *nexstream.Reader {
	out := nexstream.NewWriter(true)
	write(out)
	return nexstream.NewReader(out.Bytes(), true)
}

func gidParams(gid uint32) *nexstream.Reader {
	return params(func(out *nexstream.Writer) { out.U32(gid) })
}

func url(t *testing.T, text string) *station.URL {
	t.Helper()
	parsed, err := station.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func discardLogs(t *testing.T) {
	t.Helper()
	logx.SetOutput(io.Discard)
	t.Cleanup(func() { logx.SetOutput(os.Stderr) })
}

type fakeNAT map[string]int

func (f fakeNAT) Consume(host string) (int, bool) {
	port, found := f[host]
	return port, found
}

func natReport() *nexstream.Reader {
	return params(func(out *nexstream.Writer) {
		out.U32(1)
		out.U32(1)
		out.U32(10)
	})
}

func TestPublicIDsAreRandomAndUnique(t *testing.T) {
	seen := map[uint32]bool{}
	for i := 0; i < 60; i++ {
		s, err := New(Options{Public: true}).create(sessionFor(1, 8), 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen[s.ID] = true
	}
	if len(seen) <= 55 {
		t.Fatalf("%d different ids out of 60", len(seen))
	}
	table := New(Options{Public: true})
	seen = map[uint32]bool{}
	for pid := uint32(1); pid <= 40; pid++ {
		s, err := table.create(sessionFor(1, 8), pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen[s.ID] = true
	}
	if len(seen) != 40 {
		t.Fatalf("%d unique ids", len(seen))
	}
}

func TestSessionKeyIsZeroUnlessARandomOneIsAskedFor(t *testing.T) {
	s, _ := New(Options{Public: true}).create(sessionFor(1, 8), 1, 0)
	if !bytes.Equal(s.SessionKey, make([]byte, 32)) {
		t.Fatalf("key %x", s.SessionKey)
	}
	s, _ = New(Options{Public: true, RandomSessionKey: true}).create(sessionFor(1, 8), 1, 0)
	if len(s.SessionKey) != 32 || bytes.Equal(s.SessionKey, make([]byte, 32)) {
		t.Fatalf("key %x", s.SessionKey)
	}
}

func TestPublicJoinRefusesClosedAndFullSessionsButNotMembers(t *testing.T) {
	const member, stranger = 1, 9
	m := New(Options{Public: true})
	s, _ := m.create(sessionFor(1, 8), member, 0)
	m.join(s, member, 1)
	if err := m.checkJoinable(s, stranger); err != nil {
		t.Fatal(err)
	}
	m.close(s, "test")
	if m.checkJoinable(s, stranger) == nil {
		t.Fatal("the session is closed")
	}
	if err := m.checkJoinable(s, member); err != nil {
		t.Fatal("a member may come back")
	}
	s.Open = true
	for pid := uint32(100); pid < 108; pid++ {
		m.join(s, pid, 0)
	}
	if m.checkJoinable(s, stranger) == nil {
		t.Fatal("the session is full")
	}
}

func TestLabJoinIsNotRestricted(t *testing.T) {
	m := New(Options{})
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.close(s, "test")
	if err := m.checkJoinable(s, 99); err != nil {
		t.Fatal(err)
	}
}

func TestProbeTargetsMustShareASession(t *testing.T) {
	m := New(Options{Public: true})
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 1)
	m.join(s, 2, 0)
	if !m.shareSession(1, 2) || m.shareSession(1, 3) {
		t.Fatal("wrong members")
	}
}

func TestProbeStationMustBeAnAddressOfTheCaller(t *testing.T) {
	m := New(Options{Public: true})
	conn, _ := connection(m, 1, "203.0.113.5:50000")
	m.stations[1] = []*station.URL{url(t, "prudp:/address=192.168.1.20")}
	for address, want := range map[string]bool{"203.0.113.5": true, "192.168.1.20": true, "": true, "198.51.100.77": false} {
		probe := station.New("prudp")
		probe.Set("address", address)
		if m.probeAllowed(conn, probe) != want {
			t.Fatalf("%q", address)
		}
	}
}

func TestOnlyTheHostChangesItsSession(t *testing.T) {
	m := New(Options{})
	host, _ := connection(m, 1, "127.0.0.1:5")
	stranger, _ := connection(m, 2, "127.0.0.1:6")
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 1)
	s.Attribs = []uint32{0}
	s.ProgressScore = 100

	attribute := func() *nexstream.Reader {
		return params(func(out *nexstream.Writer) {
			out.U32(s.ID)
			out.U32(0)
			out.U32(99)
		})
	}
	score := func() *nexstream.Reader {
		return params(func(out *nexstream.Writer) {
			out.U32(s.ID)
			out.U8(77)
		})
	}
	discard := nexstream.NewWriter(true)
	for _, err := range []error{m.closeParticipation(stranger, gidParams(s.ID), discard),
		m.modifyAttribute(stranger, attribute(), discard), m.updateProgressScore(stranger, score(), discard)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !s.Open || s.Attribs[0] != 0 || s.ProgressScore != 100 {
		t.Fatalf("a stranger changed the session: %+v", s)
	}
	if err := m.closeParticipation(host, gidParams(s.ID), discard); err != nil || s.Open {
		t.Fatalf("the host could not close it: %v", err)
	}
}

func TestSessionURLsAreOnlyForMembers(t *testing.T) {
	m := New(Options{Public: true})
	host, _ := connection(m, 1, "203.0.113.9:5")
	stranger, _ := connection(m, 2, "203.0.113.10:5")
	s, _ := m.create(sessionFor(1, 8), 1, 0)
	m.join(s, 1, 1)
	m.stations[1] = []*station.URL{url(t, "prudps:/address=203.0.113.9;port=9000")}

	var refused *rmc.Error
	err := m.getSessionURLs(stranger, gidParams(s.ID), nexstream.NewWriter(true))
	if !errors.As(err, &refused) || refused.Code != rmc.SessionVoid {
		t.Fatalf("err = %v", err)
	}
	out := nexstream.NewWriter(true)
	if err := m.getSessionURLs(host, gidParams(s.ID), out); err != nil {
		t.Fatal(err)
	}
	if urls := readStations(nexstream.NewReader(out.Bytes(), true)); urls[0].Int("port") != 9000 {
		t.Fatalf("urls %v", urls)
	}
}

func TestLabNATReportKeepsEachPlayersOwnEndpoint(t *testing.T) {
	m := New(Options{NAT: fakeNAT{"127.0.0.2": 1111, "127.0.0.3": 2222}})
	first, _ := connection(m, 1, "127.0.0.2:5")
	second, _ := connection(m, 2, "127.0.0.3:5")
	for _, conn := range []*rmc.Conn{first, second} {
		if err := m.reportNATProperties(conn, natReport(), nexstream.NewWriter(true)); err != nil {
			t.Fatal(err)
		}
	}
	if m.peers[1] != (endpoint{"127.0.0.2", 1111}) || m.peers[2] != (endpoint{"127.0.0.3", 2222}) {
		t.Fatalf("peers %v", m.peers)
	}
}

func publicURL(t *testing.T, m *Matchmaker, pid uint32) *station.URL {
	t.Helper()
	for _, item := range m.stations[pid] {
		if item.Int("type") == urlTypePublic {
			return item
		}
	}
	t.Fatalf("no public URL in %v", m.stations[pid])
	return nil
}

func TestPublicNATReportOnlySetsThePublicPort(t *testing.T) {
	m := New(Options{Public: true, NAT: fakeNAT{"203.0.113.9": 3333}})
	conn, _ := connection(m, 1, "203.0.113.9:5")
	if err := m.register(conn, nil, nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	if err := m.reportNATProperties(conn, natReport(), nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	if len(m.peers) != 0 {
		t.Fatalf("peers %v", m.peers)
	}
	public := publicURL(t, m, 1)
	if public.Get("address") != "203.0.113.9" || public.Int("port") != 3333 || m.natPorts[1] != 3333 {
		t.Fatalf("public %s", public)
	}
}

func TestRegisterForgetsWhatThePreviousSessionLearned(t *testing.T) {
	m := New(Options{})
	conn, _ := connection(m, 1, "127.0.0.1:5000")
	m.peers[1] = endpoint{"127.0.0.1", 61000}
	m.natPorts[1] = 61000
	if err := m.register(conn, nil, nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	if len(m.peers) != 0 || len(m.natPorts) != 0 {
		t.Fatalf("peers %v, ports %v", m.peers, m.natPorts)
	}
	publicURL(t, m, 1)
}

func TestLoopbackPIAURLIsRewrittenToThePacketSource(t *testing.T) {
	m := New(Options{Public: true})
	conn, _ := connection(m, 1, "192.168.1.8:5000")
	registered := url(t, "prudp:/address=127.0.0.1;port=57285;type=2")
	out := nexstream.NewWriter(true)
	if err := m.register(conn, []*station.URL{registered}, out); err != nil {
		t.Fatal(err)
	}
	in := nexstream.NewReader(out.Bytes(), true)
	in.U32()
	in.U32()
	if public := readStation(in); public.Get("address") != "192.168.1.8" {
		t.Fatalf("public %s", public)
	}
	stored := m.stations[1][0]
	if stored.Get("address") != "192.168.1.8" || stored.Int("port") != 57285 {
		t.Fatalf("stored %s", stored)
	}

	// The game's ReplaceURL still carries 127.0.0.1: it matches on port and type, peers keep the public address.
	replace := params(func(out *nexstream.Writer) {
		out.Text(registered.String())
		out.Text("prudp:/address=127.0.0.1;port=51534;type=3;natf=1;natm=1")
	})
	if err := m.handleReplaceURL(conn, replace, nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	stored = m.stations[1][0]
	if stored.Get("address") != "192.168.1.8" || stored.Int("port") != 51534 || stored.Int("type") != 3 {
		t.Fatalf("replaced %s", stored)
	}
}

func TestLabKeepsTheRegisteredAddress(t *testing.T) {
	m := New(Options{})
	conn, _ := connection(m, 1, "127.0.0.1:5000")
	registered := url(t, "prudp:/address=127.0.0.1;port=64278;type=2")
	if err := m.register(conn, []*station.URL{registered}, nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	if address := m.stations[1][0].Get("address"); address != "127.0.0.1" {
		t.Fatalf("address %s", address)
	}
}

func TestSendReportLogIsBounded(t *testing.T) {
	var logs bytes.Buffer
	logx.SetOutput(&logs)
	t.Cleanup(func() { logx.SetOutput(os.Stderr) })
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	report := params(func(out *nexstream.Writer) {
		out.U32(7)
		out.QBuffer(payload)
	})
	if err := New(Options{}).handleSendReport(nil, report, nil); err != nil {
		t.Fatal(err)
	}
	line := logs.String()
	if !strings.Contains(line, "bytes=100") || !strings.Contains(line, "...") || strings.Contains(line, hex.EncodeToString(payload)) {
		t.Fatalf("log %q", line)
	}
}

// The parameters below are byte for byte what the game writes (02BF5478 for AutoMatchmakeParam).

func searchCriterion(out *nexstream.Writer) {
	out.Struct(3, func(sub *nexstream.Writer) { // the version Splatoon writes
		sub.U32(0)                 // attribs
		sub.Write(make([]byte, 8)) // game mode and the participants, empty strings of length 0
		sub.Write([]byte{1, 1, 0}) // vacant only, exclude locked, exclude non host pid
		sub.U32(0)                 // selection method
		sub.U16(1)                 // vacant participants
		sub.Write([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
	})
}

func autoParams(criteria int) *nexstream.Reader {
	return params(func(out *nexstream.Writer) {
		out.Struct(0, func(sub *nexstream.Writer) {
			sessionFor(1, 8).encode(sub)
			sub.U32(0) // participants
			sub.U32(0) // gid for participation check
			sub.U32(0) // options
			sub.Text("")
			sub.U16(1)
			sub.U32(uint32(criteria))
			for i := 0; i < criteria; i++ {
				searchCriterion(sub)
			}
			sub.U32(0) // target gids; no block list after them
		})
	})
}

func autoBytes() []byte {
	in := autoParams(1)
	return in.Read(in.Remaining())
}

func TestSearchCriteriaConsumeTheBytesTheLibraryDoesNotKnow(t *testing.T) {
	in := params(searchCriterion)
	skipSearchCriteria(in)
	if in.Err() != nil || in.Remaining() != 0 {
		t.Fatalf("err=%v remaining=%d", in.Err(), in.Remaining())
	}
}

func TestSplatoonFormats(t *testing.T) {
	m := New(Options{})
	discardLogs(t)
	first, _ := connection(m, 0x1234, "127.0.0.1:5")
	second, _ := connection(m, 0x5678, "127.0.0.1:6")

	out := nexstream.NewWriter(true)
	playing := params(func(w *nexstream.Writer) { w.U32s([]uint32{0x1234}) })
	if err := getPlayingSession(first, playing, out); err != nil || !bytes.Equal(out.Bytes(), make([]byte, 4)) {
		t.Fatalf("err=%v body=%x", err, out.Bytes())
	}

	gids := map[uint32]bool{}
	for i, conn := range []*rmc.Conn{first, second} {
		out := nexstream.NewWriter(true)
		if err := m.autoMatchmake(conn, autoParams(i), out); err != nil { // with and without a search criterion
			t.Fatal(err)
		}
		gids[decodeSession(nexstream.NewReader(out.Bytes(), true)).ID] = true
	}
	if len(gids) != 1 {
		t.Fatalf("gids %v", gids)
	}

	// Private Battle: 109/38 creates a room, a friend joins it by gid with 109/39.
	create := params(func(out *nexstream.Writer) {
		out.Struct(0, func(sub *nexstream.Writer) {
			room := sessionFor(3, 8)
			room.encode(sub)
			sub.U32(0)
			sub.U32(0)
			sub.U32(0)
			sub.Text("")
			sub.U16(1)
		})
	})
	host, _ := connection(m, 0xAAAA, "127.0.0.1:7")
	guest, _ := connection(m, 0xBBBB, "127.0.0.1:8")
	out = nexstream.NewWriter(true)
	if err := m.createWithParam(host, create, out); err != nil {
		t.Fatal(err)
	}
	room := decodeSession(nexstream.NewReader(out.Bytes(), true)).ID
	join := params(func(out *nexstream.Writer) { // without the newer trailing fields
		out.Struct(0, func(sub *nexstream.Writer) {
			sub.U32(room)
			sub.U32(0)
			sub.U32(0)
			sub.U32(0)
			sub.U8(0)
			sub.Text("")
			sub.Text("")
			sub.Text("")
			sub.U16(1)
		})
	})
	if err := m.joinWithParam(guest, join, nexstream.NewWriter(true)); err != nil {
		t.Fatal(err)
	}
	if members := m.members[room]; len(members) != 2 || members[0] != 0xAAAA || members[1] != 0xBBBB {
		t.Fatalf("members %x", members)
	}
}

type target struct {
	protocol uint16
	method   uint32
	handler  rmc.Handler
}

func targets(m *Matchmaker) []target {
	var all []target
	for protocol, methods := range m.Services() {
		for method, handler := range methods {
			all = append(all, target{protocol, method, handler})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].protocol != all[j].protocol {
			return all[i].protocol < all[j].protocol
		}
		return all[i].method < all[j].method
	})
	return all
}

// Handlers are called directly, past the recover in rmc: a panic here fails the test. The state must
// stay bounded whatever comes in.
func TestRandomRequestsDoNotPanicOrGrowTheState(t *testing.T) {
	discardLogs(t)
	const players = 8
	valid := autoBytes()
	for _, public := range []bool{false, true} {
		m := New(Options{Public: public, NAT: fakeNAT{}})
		all := targets(m)
		conns := make([]*rmc.Conn, players)
		for i := range conns {
			conns[i], _ = connection(m, uint32(i+1), "127.0.0.1:5")
		}
		random := rand.New(rand.NewSource(0x5EED2026))
		for i := 0; i < 10000; i++ {
			var body []byte
			if i%4 == 0 { // a valid request with a few bytes changed goes much further than noise
				body = bytes.Clone(valid)
				for flips := random.Intn(8); flips >= 0; flips-- {
					body[random.Intn(len(body))] = byte(random.Intn(256))
				}
			} else {
				body = make([]byte, random.Intn(48))
				random.Read(body)
			}
			call := all[random.Intn(len(all))]
			_ = call.handler(conns[random.Intn(players)], nexstream.NewReader(body, true), nexstream.NewWriter(true))
		}
		m.mu.Lock()
		sessions, stations := len(m.sessions), len(m.stations)
		m.mu.Unlock()
		if sessions > maxSessions || stations > players {
			t.Fatalf("public=%t: %d sessions, %d stations", public, sessions, stations)
		}
	}
}

func FuzzRequests(f *testing.F) {
	f.Add(uint8(0), []byte{})
	f.Add(uint8(13), autoBytes())
	f.Fuzz(func(t *testing.T, which uint8, body []byte) {
		discardLogs(t)
		m := New(Options{Public: which&1 == 0, NAT: fakeNAT{}})
		conn, _ := connection(m, 1, "127.0.0.1:5")
		all := targets(m)
		_ = all[int(which)%len(all)].handler(conn, nexstream.NewReader(body, true), nexstream.NewWriter(true))
	})
}
