package social

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
)

const (
	alice    = uint32(0x5eea2491)
	bob      = uint32(0x5eea2492)
	carol    = uint32(0x5eea2493)
	password = "abcdefghijklmnop"
)

var mode = strings.Repeat("ab", 44)

type fixture struct {
	*Social
	now float64
	t   *testing.T
}

func setup(t *testing.T, integrity string, releases map[string][]string) *fixture {
	t.Helper()
	store, err := accounts.Open(filepath.Join(t.TempDir(), "players.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, pid := range []uint32{alice, bob, carol} {
		if _, err := store.Register(pid, password); err != nil {
			t.Fatal(err)
		}
	}
	f := &fixture{now: 1000, t: t}
	f.Social = New(store, func() float64 { return f.now }, integrity, releases)
	return f
}

func (f *fixture) session(pid uint32) string {
	f.t.Helper()
	token, err := f.OpenSession(pid, password, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

func (f *fixture) beat(token string, friends ...any) []Friend {
	f.t.Helper()
	result, err := f.Heartbeat(token, mode, friends)
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

func status(err error) int {
	var refused *Error
	if errors.As(err, &refused) {
		return refused.Status
	}
	return 0
}

func TestSessionNeedsTheRightPassword(t *testing.T) {
	f := setup(t, "", nil)
	if _, err := f.OpenSession(alice, "wrongwrongwrong0", nil); status(err) != 401 {
		t.Fatal(err)
	}
	if _, err := f.OpenSession(0x1234, password, nil); status(err) != 401 {
		t.Fatal(err)
	}
	if f.PIDOf(f.session(alice)) != alice {
		t.Fatal("token")
	}
}

func TestPseudosClaimAndRefusals(t *testing.T) {
	f := setup(t, "", nil)
	if name, err := f.ClaimPseudo(alice, password, " Inkling "); err != nil || name != "Inkling" {
		t.Fatal(name, err)
	}
	if _, err := f.ClaimPseudo(bob, password, "inkling"); status(err) != 409 {
		t.Fatal(err)
	}
	for _, bad := range []any{"x", "bad<name>", "elevenchars", 12, nil, []any{"a"}} {
		if _, err := f.ClaimPseudo(carol, password, bad); status(err) != 400 {
			t.Errorf("%v: %v", bad, err)
		}
	}
	for _, name := range []string{"Admin", "NINTENDO", "server"} {
		if _, err := f.ClaimPseudo(carol, password, name); status(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.ClaimPseudo(carol, "wrongwrongwrong0", "Carol"); status(err) != 401 {
		t.Fatal(err)
	}
}

func TestLookupTellsIfThePlayerIsOnline(t *testing.T) {
	f := setup(t, "", nil)
	if _, err := f.ClaimPseudo(bob, password, "Bob"); err != nil {
		t.Fatal(err)
	}
	a, b := f.session(alice), f.session(bob)
	result, err := f.Lookup(a, "bob", "203.0.113.9")
	if err != nil || result["found"] != true || result["pid"] != "5eea2492" || result["pseudo"] != "Bob" ||
		result["online"] != false || result["self"] != false {
		t.Fatalf("%v %v", result, err)
	}
	f.beat(b)
	if result, _ = f.Lookup(a, "Bob", "203.0.113.9"); result["online"] != true {
		t.Fatal(result)
	}
	if result, _ = f.Lookup(b, "Bob", "203.0.113.9"); result["self"] != true {
		t.Fatal(result)
	}
	if result, _ = f.Lookup(a, "Nobody", "203.0.113.9"); result["found"] != false || len(result) != 1 {
		t.Fatal(result)
	}
	if _, err = f.Lookup("bad", "Bob", ""); status(err) != 401 {
		t.Fatal(err)
	}
}

func TestPresenceIsSharedOnlyBetweenMutualFriends(t *testing.T) {
	f := setup(t, "", nil)
	if _, err := f.ClaimPseudo(bob, password, "Bob"); err != nil {
		t.Fatal(err)
	}
	a, b, c := f.session(alice), f.session(bob), f.session(carol)
	f.beat(c, "5eea2491") // Carol lists Alice, but Alice does not list Carol
	if friends := f.beat(a, "5eea2492"); len(friends) != 0 {
		t.Fatal("Bob has not added Alice back", friends)
	}
	friends := f.beat(b, "5eea2491")
	if len(friends) != 1 || friends[0] != (Friend{"5eea2491", "Ami", mode}) {
		t.Fatal(friends)
	}
	friends = f.beat(a, "5eea2492")
	if len(friends) != 1 || friends[0] != (Friend{"5eea2492", "Bob", mode}) {
		t.Fatal(friends)
	}
	if friends = f.beat(c, "5eea2491"); len(friends) != 0 {
		t.Fatal("Alice has not added Carol back", friends)
	}
}

func TestPresenceExpiresAndInputIsChecked(t *testing.T) {
	f := setup(t, "", nil)
	a, b := f.session(alice), f.session(bob)
	f.beat(a, "5eea2492")
	f.beat(b, "5eea2491")
	if f.OnlineCount() != 2 {
		t.Fatal(f.OnlineCount())
	}
	f.now += OnlineWindow + 1
	if friends := f.beat(a, "5eea2492"); len(friends) != 0 || f.OnlineCount() != 1 {
		t.Fatal(friends)
	}
	if _, err := f.Heartbeat(a, "zz", nil); status(err) != 400 {
		t.Fatal(err)
	}
	if _, err := f.Heartbeat("bad", mode, nil); status(err) != 401 {
		t.Fatal(err)
	}
	f.now += TokenTTL + 1
	if _, err := f.Heartbeat(a, mode, nil); status(err) != 401 {
		t.Fatal("the token expired: ", err)
	}
}

func TestRateLimits(t *testing.T) {
	f := setup(t, "", nil)
	a := f.session(alice)
	refused := false
	for i := 0; i < 25; i++ {
		if _, err := f.Lookup(a, "Nobody", "203.0.113.9"); status(err) == 429 {
			refused = true
		}
	}
	if !refused {
		t.Fatal("searches")
	}
	refused = false
	for i := 0; i < 45; i++ {
		if _, err := f.Heartbeat(a, mode, nil); status(err) == 429 {
			refused = true
		}
	}
	if !refused {
		t.Fatal("heartbeats")
	}
	allowed := 0
	for i := 0; i < 40; i++ {
		if f.AllowAuth("2001:db8:1:2::" + strings.Repeat("a", i%4+1)) {
			allowed++
		}
	}
	if allowed != 30 {
		t.Fatal("one IPv6 home shares a key: ", allowed)
	}
}

func TestANewSessionReplacesTheOldToken(t *testing.T) {
	f := setup(t, "", nil)
	first := f.session(alice)
	second := f.session(alice)
	if f.PIDOf(first) != 0 || f.PIDOf(second) != alice {
		t.Fatal("one session per player")
	}
}

func TestABannedPlayerIsRefusedEverywhere(t *testing.T) {
	f := setup(t, "", nil)
	token := f.session(alice)
	if err := f.Accounts.AddBan(ptr(alice), "", "", nil); err != nil {
		t.Fatal(err)
	}
	_, sessionErr := f.OpenSession(alice, password, nil)
	_, pseudoErr := f.ClaimPseudo(alice, password, "Alice")
	_, lookupErr := f.Lookup(token, "Alice", "")
	_, presenceErr := f.Heartbeat(token, mode, nil)
	for _, err := range []error{sessionErr, pseudoErr, lookupErr, presenceErr} {
		if status(err) != 403 {
			t.Errorf("%v", err)
		}
	}
	f.Revoke(alice)
	if f.PIDOf(token) != 0 {
		t.Fatal("revoked")
	}
}

func ptr(pid uint32) *uint32 { return &pid }

func TestHeartbeatIgnoresHostileInput(t *testing.T) {
	f := setup(t, "", nil)
	a, b := f.session(alice), f.session(bob)
	f.beat(b, "5eea2491")
	many := make([]any, 500)
	for i := range many {
		many[i] = "7fffff00"
	}
	many[0] = "5eea2492"
	for _, friends := range []any{
		[]any{nil, true, 1.5, "zz", []any{}, map[string]any{}, "-1", "0", "ffffffff", "5eea2491", "0x5eea2492"},
		many, "5eea2492", 12, map[string]any{"x": 1}, nil,
	} {
		if _, err := f.Heartbeat(a, mode, friends); err != nil {
			t.Fatalf("%v: %v", friends, err)
		}
		f.now += 2 // stays under the presence rate
	}
	result, err := f.Heartbeat(a, nil, []any{"0x5eea2492"})
	if err != nil || len(result) != 1 {
		t.Fatalf("0x prefix accepted: %v %v", result, err)
	}
	if listed := len(f.presences[alice].friends); listed != 1 {
		t.Fatal(listed)
	}
}

func TestIntegrity(t *testing.T) {
	hash, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	releases := map[string][]string{"0.1.3": {other}, "0.1.10": {hash}, "0.1.4": {other}}
	proof := map[string]any{"version": "0.1.10", "code": hash}
	f := setup(t, "enforce", releases)
	if f.LatestVersion() != "0.1.10" {
		t.Fatal(f.LatestVersion())
	}
	if f.IsAttested(alice) {
		t.Fatal("no proof yet")
	}
	if _, err := f.OpenSession(alice, password, proof); err != nil || !f.IsAttested(alice) {
		t.Fatal(err)
	}
	_, err := f.OpenSession(alice, password, map[string]any{"version": "0.9", "code": strings.Repeat("c", 64)})
	if status(err) != 426 || !strings.Contains(err.Error(), "version 0.9") || !strings.Contains(err.Error(), "to 0.1.10") {
		t.Fatal(err)
	}
	if f.IsAttested(alice) {
		t.Fatal("a refused proof drops the attestation")
	}
	for _, bad := range []any{nil, "x", map[string]any{"code": 12}, map[string]any{"code": "short"}} {
		if _, err := f.OpenSession(alice, password, bad); status(err) != 426 || !strings.Contains(err.Error(), "no integrity proof") {
			t.Errorf("%v: %v", bad, err)
		}
	}
	token, err := f.OpenSession(alice, password, proof)
	if err != nil {
		t.Fatal(err)
	}
	f.now += TokenTTL - 10
	f.beat(token)
	f.now += 20
	if !f.IsAttested(alice) {
		t.Fatal("the heartbeat renews the proof")
	}
	logging := setup(t, "log", releases)
	if _, err := logging.OpenSession(alice, password, nil); err != nil || !logging.IsAttested(alice) {
		t.Fatal("log mode lets everyone in: ", err)
	}
	if !setup(t, "off", nil).IsAttested(alice) {
		t.Fatal("off")
	}
}
