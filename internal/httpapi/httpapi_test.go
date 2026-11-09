package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/social"
)

const (
	password = "abcdefghijklmnop"
	pidText  = "5eea2491"
	pidValue = uint32(0x5eea2491)
)

type fakeLive struct {
	mu    sync.Mutex
	kicks []uint32
}

func (f *fakeLive) Stats() Stats   { return Stats{Players: 2, Sessions: 1, Connections: 3} }
func (f *fakeLive) Errors() uint64 { return 4 }
func (f *fakeLive) Sessions() []SessionInfo {
	return []SessionInfo{{ID: 0x1001, Host: pidValue, Members: 2, Closed: true}}
}
func (f *fakeLive) ActivePlayers() []uint32 { return []uint32{pidValue} }
func (f *fakeLive) RequestKick(pid uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kicks = append(f.kicks, pid)
}

func server(t *testing.T, change func(*Options)) (*Server, *fakeLive) {
	t.Helper()
	store, err := accounts.Open(filepath.Join(t.TempDir(), "players.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	live := &fakeLive{}
	options := Options{Accounts: store, Live: live, Social: social.New(store, nil, "", nil)}
	if change != nil {
		change(&options)
	}
	return New(options), live
}

type response struct {
	status int
	body   map[string]any
}

func call(s *Server, method, path, body string, headers map[string]string) response {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "203.0.113.9:4242"
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	if body == "" {
		request.ContentLength = 0
	}
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, request)
	result := response{status: recorder.Code, body: map[string]any{}}
	_ = json.Unmarshal(recorder.Body.Bytes(), &result.body)
	return result
}

func post(s *Server, path, body string) response { return call(s, http.MethodPost, path, body, nil) }

func register(pid string) string {
	return fmt.Sprintf(`{"pid": %q, "password": %q}`, pid, password)
}

func expect(t *testing.T, got response, status int, key string, value any) {
	t.Helper()
	if got.status != status {
		t.Fatalf("status %d, want %d (%v)", got.status, status, got.body)
	}
	if key != "" && got.body[key] != value {
		t.Fatalf("%s = %v, want %v", key, got.body[key], value)
	}
}

func TestRegister(t *testing.T) {
	s, _ := server(t, nil)
	expect(t, post(s, "/register", register(pidText)), 200, "status", "created")
	expect(t, post(s, "/register", register("0x"+pidText)), 200, "status", "exists")
	expect(t, post(s, "/register", fmt.Sprintf(`{"pid":%q,"password":"ponmlkjihgfedcba"}`, pidText)), 409, "", nil)
	expect(t, post(s, "/register", register("12")), 400, "error", "pid out of the range the game generates")
	expect(t, post(s, "/register", `{"password":"x"}`), 400, "error", "pid must be decimal or hexadecimal")
	expect(t, post(s, "/register", `{"pid":"5eea2499"}`), 400, "error", "the NEX password must be 16 letters or digits")
	expect(t, post(s, "/register", ""), 400, "error", "invalid body")
	expect(t, post(s, "/register", strings.Repeat("x", maxBody+1)), 400, "error", "invalid body")
	expect(t, post(s, "/register", `{"pid":`), 400, "error", "invalid JSON")
}

func TestRegisterBoundsAttemptsIncludingSuccesses(t *testing.T) {
	s, _ := server(t, nil)
	for i := 0; i < 10; i++ {
		expect(t, post(s, "/register", `[1]`), 400, "error", "invalid JSON")
	}
	expect(t, post(s, "/register", register(pidText)), 429, "", nil)
}

func TestRegisterToken(t *testing.T) {
	s, _ := server(t, func(o *Options) { o.Token = "s3cret" })
	expect(t, post(s, "/register", register(pidText)), 401, "error", "invalid registration token")
	expect(t, call(s, "POST", "/register", register(pidText), map[string]string{"Authorization": "Bearer s3cret"}), 200, "status", "created")
	expect(t, post(s, "/register", fmt.Sprintf(`{"pid":%q,"password":%q,"token":"s3cret"}`, pidText, password)), 200, "status", "exists")
}

func TestRegisterRefusesBanned(t *testing.T) {
	s, _ := server(t, nil)
	pid := pidValue
	if err := s.Accounts.AddBan(&pid, "", "", nil); err != nil {
		t.Fatal(err)
	}
	expect(t, post(s, "/register", register(pidText)), 403, "", nil)
	if err := s.Accounts.AddBan(nil, "203.0.113.9", "", nil); err != nil {
		t.Fatal(err)
	}
	expect(t, post(s, "/register", `{"pid":"nope"}`), 403, "", nil)
}

func TestHealth(t *testing.T) {
	s, _ := server(t, nil)
	got := call(s, "GET", "/health", "", nil)
	expect(t, got, 200, "ok", true)
	if len(got.body) != 1 {
		t.Fatal("no extra field by default: ", got.body)
	}
	s, _ = server(t, func(o *Options) {
		o.MinClientVersion = "0.2.0"
		o.Social = social.New(o.Accounts, nil, "enforce", map[string][]string{"0.1.3": {strings.Repeat("a", 64)}})
	})
	got = call(s, "GET", "/health?x=1", "", nil)
	expect(t, got, 200, "min_client_version", "0.2.0")
	expect(t, got, 200, "integrity_mode", "enforce")
	expect(t, got, 200, "latest_version", "0.1.3")
	if strings.Contains(fmt.Sprint(got.body), strings.Repeat("a", 64)) {
		t.Fatal("hashes stay private")
	}
}

func TestMetricsNeedNoTokenAndHideIdentities(t *testing.T) {
	s, _ := server(t, func(o *Options) { o.Token = "s3cret" })
	got := call(s, "GET", "/metrics", "", nil)
	expect(t, got, 200, "players", 2.0)
	expect(t, got, 200, "sessions", 1.0)
	expect(t, got, 200, "connections", 3.0)
	expect(t, got, 200, "errors", 4.0)
	if _, present := got.body["uptime"]; !present || len(got.body) != 5 {
		t.Fatal(got.body)
	}
}

func TestAdminNeedsTokenAndKicks(t *testing.T) {
	s, live := server(t, func(o *Options) { o.Token = "s3cret" })
	for _, path := range []string{"/admin/sessions", "/admin/kick?pid=" + pidText, "/admin/bans", "/admin/log"} {
		expect(t, call(s, "GET", path, "", nil), 401, "error", "admin token required")
		expect(t, call(s, "GET", path, "", map[string]string{"Authorization": "Bearer nope"}), 401, "", nil)
	}
	admin := map[string]string{"Authorization": "Bearer s3cret"}
	expect(t, call(s, "GET", "/admin/kick?pid=nope", "", admin), 400, "error", "invalid pid")
	expect(t, call(s, "GET", "/admin/kick", "", admin), 400, "error", "invalid pid")
	expect(t, call(s, "GET", "/admin/kick?pid=0x"+pidText, "", admin), 200, "kick", pidText)
	if len(live.kicks) != 1 || live.kicks[0] != pidValue {
		t.Fatal(live.kicks)
	}
	entries := call(s, "GET", "/admin/log", "", admin).body["log"].([]any)
	if entry := entries[0].(map[string]any); entry["action"] != "kick" || entry["pid"] != pidText {
		t.Fatal(entry)
	}
	if _, err := s.Accounts.ClaimPseudo(pidValue, "Inkling"); err != nil {
		t.Fatal(err)
	}
	sessions := call(s, "GET", "/admin/sessions", "", admin).body
	if first := sessions["sessions"].([]any)[0].(map[string]any); first["id"] != 4097.0 || first["host"] != pidText ||
		first["members"] != 2.0 || first["closed"] != true {
		t.Fatal(first)
	}
	if sessions["players"].([]any)[0] != pidText || sessions["pseudos"].(map[string]any)[pidText] != "Inkling" {
		t.Fatal(sessions)
	}
}

func TestAdminRoutesDoNotExistWithoutAToken(t *testing.T) {
	s, _ := server(t, nil)
	expect(t, call(s, "GET", "/admin/bans", "", nil), 401, "", nil)
	expect(t, post(s, "/admin/ban", `{"pid":"1"}`), 401, "", nil)
	s, _ = server(t, func(o *Options) { o.AdminToken = "boss" })
	expect(t, call(s, "GET", "/admin/bans", "", map[string]string{"Authorization": "Bearer boss"}), 200, "", nil)
	expect(t, post(s, "/register", register(pidText)), 200, "status", "created") // open registration
}

func TestBanKicksAndRevokes(t *testing.T) {
	s, live := server(t, func(o *Options) { o.AdminToken = "boss" })
	admin := map[string]string{"Authorization": "Bearer boss"}
	if _, err := s.Accounts.Register(pidValue, password); err != nil {
		t.Fatal(err)
	}
	token, err := s.Social.OpenSession(pidValue, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, call(s, "POST", "/admin/ban", `{"pid":"`+pidText+`","hours":2,"reason":"cheat"}`, admin), 200, "ok", true)
	if len(live.kicks) != 1 || s.Social.PIDOf(token) != 0 {
		t.Fatal("a pid ban kicks and revokes")
	}
	bans := call(s, "GET", "/admin/bans", "", admin).body["bans"].([]any)
	if ban := bans[0].(map[string]any); ban["pid"] != pidText || ban["reason"] != "cheat" || ban["ip"] != nil || ban["expires"] == nil {
		t.Fatal(ban)
	}
	expect(t, call(s, "POST", "/admin/ban", `{"ip":"203.0.113.77"}`, admin), 200, "ok", true)
	if len(live.kicks) != 1 {
		t.Fatal("an address ban kicks nobody")
	}
	expect(t, call(s, "POST", "/admin/unban", `{"pid":"`+pidText+`"}`, admin), 200, "ok", true)
	expect(t, call(s, "POST", "/admin/ban", `{}`, admin), 400, "error", "a ban needs a pid, an ip, or both")
	expect(t, call(s, "POST", "/admin/ban", `{"pid":"nope"}`, admin), 400, "", nil)
	expect(t, call(s, "POST", "/admin/ban", `{"ip":"nope"}`, admin), 400, "error", "not an IP address")
	expect(t, call(s, "POST", "/admin/ban", `{"pid":"1","hours":"soon"}`, admin), 400, "error", "hours must be a number")
	expect(t, call(s, "POST", "/admin/ban", `not json`, admin), 400, "error", "invalid JSON")
}

func TestSocialRoutes(t *testing.T) {
	s, _ := server(t, nil)
	if _, err := s.Accounts.Register(pidValue, password); err != nil {
		t.Fatal(err)
	}
	credentials := fmt.Sprintf(`"pid":"0x%s","password":%q`, pidText, password)
	expect(t, post(s, "/social/session", ""), 400, "error", "invalid body")
	expect(t, post(s, "/social/session", `[]`), 400, "error", "invalid JSON")
	expect(t, post(s, "/social/session", "\"\xff\""), 400, "error", "invalid JSON")
	expect(t, post(s, "/social/session", `{} x`), 400, "error", "invalid JSON")
	expect(t, post(s, "/social/nope", `{}`), 404, "error", "not found")
	expect(t, post(s, "/social/session", `{"pid":"nope"}`), 401, "error", "unknown player or wrong password")
	expect(t, post(s, "/social/session", `{"pid":"`+pidText+`"}`), 401, "", nil)
	got := post(s, "/social/session", "{"+credentials+"}")
	expect(t, got, 200, "", nil)
	token := got.body["token"].(string)
	expect(t, post(s, "/social/pseudo", "{"+credentials+`,"pseudo":"Inkling"}`), 200, "pseudo", "Inkling")
	expect(t, post(s, "/social/lookup", `{"token":"`+token+`","pseudo":"inkling"}`), 200, "self", true)
	expect(t, post(s, "/social/lookup", `{"pseudo":"inkling"}`), 401, "error", "session expired")
	got = post(s, "/social/presence", `{"token":"`+token+`","friends":[]}`)
	expect(t, got, 200, "", nil)
	if friends, isList := got.body["friends"].([]any); !isList || len(friends) != 0 {
		t.Fatal("an empty list, not null: ", got.body)
	}
	if err := s.Accounts.AddBan(nil, "203.0.113.9", "", nil); err != nil {
		t.Fatal(err)
	}
	expect(t, post(s, "/social/session", "{"+credentials+"}"), 403, "error", "this player or address is banned")
}

func TestSignInRateLimit(t *testing.T) {
	s, _ := server(t, nil)
	var last response
	for i := 0; i < 31; i++ {
		last = post(s, "/social/session", `{"pid":"nope"}`)
	}
	expect(t, last, 429, "error", "too many attempts, try again later")
}

func TestUnknownRoutes(t *testing.T) {
	s, _ := server(t, nil)
	expect(t, call(s, "GET", "/nope", "", nil), 404, "error", "not found")
	expect(t, post(s, "/nope", `{}`), 404, "error", "not found")
	expect(t, call(s, "DELETE", "/health", "", nil), 501, "", nil)
}

func TestClientIP(t *testing.T) {
	address := func(behind bool, peer, forwarded string) string {
		s := New(Options{BehindProxy: behind})
		request := httptest.NewRequest("GET", "/", nil)
		request.RemoteAddr = net.JoinHostPort(peer, "4242")
		if forwarded != "" {
			request.Header.Set("X-Forwarded-For", forwarded)
		}
		return s.clientIP(request)
	}
	for _, c := range []struct {
		behind                bool
		peer, forwarded, want string
	}{
		{false, "127.0.0.1", "198.51.100.1", "127.0.0.1"},                // direct mode ignores the header
		{true, "127.0.0.1", "10.9.9.9, 198.51.100.1", "198.51.100.1"},    // the entry the proxy appended
		{true, "::1", "198.51.100.1", "198.51.100.1"},                    //
		{true, "203.0.113.5", "198.51.100.1", "203.0.113.5"},             // only from the loopback
		{true, "127.0.0.1", "", "127.0.0.1"},                             // missing
		{true, "127.0.0.1", "not-an-address", "127.0.0.1"},               // invalid
		{true, "127.0.0.1", "198.51.100.1, not-an-address", "127.0.0.1"}, // the last entry decides
	} {
		if got := address(c.behind, c.peer, c.forwarded); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
	}
}

func TestRealSocketClosesEachConnectionAndCapsThem(t *testing.T) {
	s, _ := server(t, nil)
	if err := s.Start("127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	address := s.Address().String()
	held := []net.Conn{}
	defer func() {
		for _, connection := range held {
			connection.Close()
		}
	}()
	for i := 0; i < maxConnections; i++ { // sends nothing: holds a slot
		connection, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, connection)
	}
	extra, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection beyond the cap must be refused")
	} else if timeout, isNet := err.(net.Error); isNet && timeout.Timeout() {
		t.Fatal("the connection beyond the cap was queued")
	}
	for _, connection := range held {
		connection.Close()
	}
	held = nil
	var result *http.Response
	for attempt := 0; attempt < 50; attempt++ { // the slots come back as the server notices the closes
		result, err = http.Get("http://" + address + "/health")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	body, _ := io.ReadAll(result.Body)
	if result.StatusCode != 200 || !result.Close || !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("%d close=%v %s", result.StatusCode, result.Close, body)
	}
}

func TestRegisterRefusesPIDsTheGameNeverGenerates(t *testing.T) {
	s, _ := server(t, nil)
	expect(t, post(s, "/register", register("0x00000002")), 400, "", nil)
	expect(t, post(s, "/register", register("0x0fffffff")), 400, "", nil)
	expect(t, post(s, "/register", register("0x10000000")), 200, "status", "created")
}

func TestRegisterTokenMayBeNonASCII(t *testing.T) {
	s, _ := server(t, func(o *Options) { o.Token = "sécret" })
	body := func(token string) string {
		return fmt.Sprintf(`{"pid":%q,"password":%q,"token":%q}`, pidText, password, token)
	}
	expect(t, post(s, "/register", body("autre")), 401, "", nil)
	expect(t, post(s, "/register", body("sécret")), 200, "status", "created")
}

// player registers an account with a pseudo and returns its session token.
func player(t *testing.T, s *Server, pid, pseudo string) string {
	t.Helper()
	credentials := fmt.Sprintf(`"pid":%q,"password":%q`, pid, password)
	expect(t, post(s, "/register", "{"+credentials+"}"), 200, "", nil)
	expect(t, post(s, "/social/pseudo", "{"+credentials+fmt.Sprintf(`,"pseudo":%q}`, pseudo)), 200, "pseudo", pseudo)
	got := post(s, "/social/session", "{"+credentials+"}")
	expect(t, got, 200, "", nil)
	return got.body["token"].(string)
}

func TestFriendRequestRoutes(t *testing.T) {
	s, _ := server(t, nil)
	alice, bob := player(t, s, "5eea2491", "Alice"), player(t, s, "5eea2492", "Bob")
	expect(t, post(s, "/social/request", fmt.Sprintf(`{"token":%q,"pid":"5eea2492"}`, alice)), 200, "state", "sent")

	got := post(s, "/social/presence", fmt.Sprintf(`{"token":%q,"friends":[]}`, bob))
	expect(t, got, 200, "", nil)
	requests, _ := got.body["requests"].([]any)
	if len(requests) != 1 || requests[0].(map[string]any)["pid"] != "5eea2491" || requests[0].(map[string]any)["name"] != "Alice" {
		t.Fatal(got.body)
	}
	if friends, present := got.body["friends"].([]any); !present || len(friends) != 0 {
		t.Fatal("a 0.1.4 client keeps reading `friends`", got.body)
	}
	expect(t, post(s, "/social/answer", fmt.Sprintf(`{"token":%q,"pid":"5eea2491","accept":true}`, bob)), 200, "ok", true)
	expect(t, post(s, "/social/answer", fmt.Sprintf(`{"token":%q,"pid":"5eea2491","accept":true}`, bob)), 404, "error", "no such request")
	got = post(s, "/social/presence", fmt.Sprintf(`{"token":%q,"friends":[]}`, bob))
	if requests, _ := got.body["requests"].([]any); requests == nil || len(requests) != 0 {
		t.Fatal("an empty box is [], not null", got.body)
	}

	expect(t, post(s, "/social/request", fmt.Sprintf(`{"token":%q,"pid":"5eea2491"}`, alice)), 400, "error", "you cannot add yourself")
	expect(t, post(s, "/social/request", `{"token":"nope","pid":"5eea2492"}`), 401, "error", "session expired")
	expect(t, post(s, "/social/cancel", fmt.Sprintf(`{"token":%q,"pid":"5eea2492"}`, alice)), 200, "ok", true)
	expect(t, post(s, "/social/cancel", `{"token":"nope","pid":"5eea2492"}`), 401, "", nil)
}

func TestFriendRequestsLeaveWhenABanLands(t *testing.T) {
	s, _ := server(t, nil)
	alice, bob := player(t, s, "5eea2491", "Alice"), player(t, s, "5eea2492", "Bob")
	post(s, "/social/request", fmt.Sprintf(`{"token":%q,"pid":"5eea2492"}`, alice))
	if err := s.Accounts.AddBan(ptr(0x5eea2491), "", "test", nil); err != nil {
		t.Fatal(err)
	}
	got := post(s, "/social/presence", fmt.Sprintf(`{"token":%q,"friends":[]}`, bob))
	if requests, _ := got.body["requests"].([]any); len(requests) != 0 {
		t.Fatal(got.body)
	}
}

func ptr(pid uint32) *uint32 { return &pid }
