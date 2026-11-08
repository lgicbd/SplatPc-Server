package accounts

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const password = "abcdefghijklmnop"

func open(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "players.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func ptr(pid uint32) *uint32 { return &pid }

func TestParsePID(t *testing.T) {
	for text, want := range map[string]uint32{"0x5eea2491": 0x5eea2491, "5eea2491": 0x5eea2491, "12345": 12345,
		" 0X41 ": 0x41, "7fffffff": 0x7fffffff, "abc": 0xabc} {
		got, err := ParsePID(text)
		if err != nil || got != want {
			t.Errorf("ParsePID(%q) = %x, %v", text, got, err)
		}
	}
	for _, text := range []string{"", "0", "0x80000000", "None", "nope", "-1", "99999999999999999999", "1.5"} {
		if _, err := ParsePID(text); !IsInvalidIdentity(err) {
			t.Errorf("ParsePID(%q): %v", text, err)
		}
	}
}

// The reference comes from the former Python server (nintendo.nex.kerberos.KeyDerivationOld).
func TestDeriveKeyMatchesReferenceVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "derive_key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		pid, err := strconv.ParseUint(fields[0], 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(DeriveKey(fields[1], uint32(pid))); got != fields[2] {
			t.Errorf("DeriveKey(%s) = %s, want %s", fields[0], got, fields[2])
		}
	}
}

func TestIPKey(t *testing.T) {
	for text, want := range map[string]string{"203.0.113.9": "203.0.113.9", "::ffff:203.0.113.9": "203.0.113.9",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64", "nope": "unknown", "": "unknown"} {
		if got := IPKey(text); got != want {
			t.Errorf("IPKey(%q) = %s, want %s", text, got, want)
		}
	}
}

func TestRegisterKeepsOnlyTheDerivedKey(t *testing.T) {
	store := open(t)
	status, err := store.Register(0x5eea2491, password)
	if err != nil || status != "created" {
		t.Fatalf("%s %v", status, err)
	}
	if status, err = store.Register(0x5eea2491, password); err != nil || status != "exists" {
		t.Fatalf("%s %v", status, err)
	}
	var taken *AlreadyRegisteredError
	if _, err = store.Register(0x5eea2491, "ponmlkjihgfedcba"); !errors.As(err, &taken) {
		t.Fatalf("another password: %v", err)
	}
	key, err := store.Key(0x5eea2491)
	if err != nil || !bytes.Equal(key, DeriveKey(password, 0x5eea2491)) {
		t.Fatalf("%x %v", key, err)
	}
	if !store.Verify(0x5eea2491, password) || store.Verify(0x5eea2491, "ponmlkjihgfedcba") || store.Verify(1, password) || store.Verify(0x5eea2491, "é") {
		t.Fatal("verify")
	}
	store.Close()
	content, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(password)) {
		t.Fatal("the password reached the disk")
	}
}

func TestRegisterRefusesBadPasswords(t *testing.T) {
	store := open(t)
	for _, bad := range []string{"", "short", strings.Repeat("a", 17), "abcdefghijklmno!", "abcdefghijklmnoé"} {
		if _, err := store.Register(0x5eea2491, bad); !IsInvalidIdentity(err) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestAllowCountsFailuresPerAddressInsideTheWindow(t *testing.T) {
	store := open(t)
	now := 1000.0
	store.Clock = func() float64 { return now }
	store.MaxAttempts = 2
	for i := 0; i < 2; i++ {
		if err := store.Failure("203.0.113.9"); err != nil {
			t.Fatal(err)
		}
	}
	allow := func(ip string) bool {
		allowed, err := store.Allow(ip)
		if err != nil {
			t.Fatal(err)
		}
		return allowed
	}
	if allow("203.0.113.9") || !allow("203.0.113.10") {
		t.Fatal("the limit is per address")
	}
	if err := store.Failure("2001:db8:1:2::1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Failure("2001:db8:1:2::2"); err != nil {
		t.Fatal(err)
	}
	if allow("2001:db8:1:2::3") {
		t.Fatal("IPv6 is grouped by /64")
	}
	now += store.Window + 1
	if !allow("203.0.113.9") {
		t.Fatal("the window passed")
	}
	if err := store.ForgetFailures("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
}

func TestPseudosAreUniqueIgnoringCase(t *testing.T) {
	store := open(t)
	claim := func(pid uint32, pseudo string) bool {
		won, err := store.ClaimPseudo(pid, pseudo)
		if err != nil {
			t.Fatal(err)
		}
		return won
	}
	if !claim(1, "Inkling") || !claim(1, "INKLING") {
		t.Fatal("an account can restyle its own pseudo")
	}
	if claim(2, "inkling") {
		t.Fatal("taken")
	}
	if name, _ := store.PseudoOf(1); name != "INKLING" {
		t.Fatal(name)
	}
	if !claim(1, "Octo") || !claim(2, "inkling") {
		t.Fatal("renaming frees the old pseudo")
	}
	if pid, _ := store.PIDForPseudo(" OCTO "); pid != 1 {
		t.Fatal(pid)
	}
	if pid, _ := store.PIDForPseudo("nobody"); pid != 0 {
		t.Fatal(pid)
	}
	names, err := store.PseudosFor([]uint32{1, 2, 3})
	if err != nil || len(names) != 2 || names[2] != "inkling" {
		t.Fatalf("%v %v", names, err)
	}
}

func TestBansTargetPIDAddressOrPair(t *testing.T) {
	store := open(t)
	banned := func(pid *uint32, ip string) bool {
		result, err := store.IsBanned(pid, ip)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if err := store.AddBan(ptr(1), "", "cheat", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.AddBan(nil, "203.0.113.9", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.AddBan(ptr(2), "203.0.113.10", "", nil); err != nil {
		t.Fatal(err)
	}
	if !banned(ptr(1), "198.51.100.1") || !banned(nil, "203.0.113.9") || !banned(ptr(3), "203.0.113.9") {
		t.Fatal("pid-only and ip-only bans apply everywhere")
	}
	if !banned(ptr(2), "203.0.113.10") || banned(ptr(2), "198.51.100.1") || banned(ptr(3), "203.0.113.10") {
		t.Fatal("a pair blocks only that pair")
	}
	if err := store.Unban(ptr(1), ""); err != nil || banned(ptr(1), "") {
		t.Fatalf("unban: %v", err)
	}
	if err := store.AddBan(nil, "", "", nil); !IsInvalidIdentity(err) {
		t.Fatal(err)
	}
	if err := store.AddBan(nil, "nope", "", nil); !IsInvalidIdentity(err) {
		t.Fatal(err)
	}
	if err := store.Unban(nil, ""); !IsInvalidIdentity(err) {
		t.Fatal(err)
	}
}

func TestBanOnIPv6CoversItsWholeSlash64(t *testing.T) {
	store := open(t)
	if err := store.AddBan(nil, "2001:db8:1:2::1", "", nil); err != nil {
		t.Fatal(err)
	}
	if result, err := store.IsBanned(nil, "2001:db8:1:2:ffff::9"); err != nil || !result {
		t.Fatalf("%v %v", result, err)
	}
}

func TestTemporaryBanExpiresAndReplaces(t *testing.T) {
	store := open(t)
	now := 1000.0
	store.Clock = func() float64 { return now }
	hours := 2.0
	if err := store.AddBan(ptr(1), "", "first", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.AddBan(ptr(1), "", "second", &hours); err != nil {
		t.Fatal(err)
	}
	bans, err := store.Bans()
	if err != nil || len(bans) != 1 || bans[0].Reason != "second" || *bans[0].Expires != 1000+7200 {
		t.Fatalf("%+v %v", bans, err)
	}
	now += 7201
	if result, _ := store.IsBanned(ptr(1), ""); result {
		t.Fatal("expired")
	}
	if bans, _ := store.Bans(); len(bans) != 0 {
		t.Fatal("expired bans are not listed")
	}
	for _, bad := range []float64{0, -1, 24*365 + 1} {
		if err := store.AddBan(ptr(1), "", "", &bad); !IsInvalidIdentity(err) {
			t.Fatal(err)
		}
	}
}

func TestModLogIsBoundedNewestFirst(t *testing.T) {
	store := open(t)
	hours := 1.5
	if err := store.AddBan(ptr(1), "", strings.Repeat("x", 300), &hours); err != nil {
		t.Fatal(err)
	}
	if err := store.LogAction("kick", ptr(1), "", ""); err != nil {
		t.Fatal(err)
	}
	entries, err := store.ModLog(100)
	if err != nil || len(entries) != 2 || entries[0].Action != "kick" || entries[1].Action != "ban" {
		t.Fatalf("%+v %v", entries, err)
	}
	if detail := *entries[1].Detail; !strings.HasPrefix(detail, "1.5 h: x") || len(detail) != 200 {
		t.Fatal(detail)
	}
	for i := 0; i < maxModLogRows+10; i++ {
		if _, err := store.handle().Exec(`INSERT INTO mod_log (at, action) VALUES (0, 'x')`); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.LogAction("kick", nil, "", ""); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := store.handle().QueryRow(`SELECT COUNT(*) FROM mod_log`).Scan(&rows); err != nil || rows != maxModLogRows {
		t.Fatalf("%d %v", rows, err)
	}
}

func TestBackupAndRestore(t *testing.T) {
	store := open(t)
	if _, err := store.Register(1, password); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "copy.sqlite3")
	if err := store.Backup(backup); err != nil {
		t.Fatal(err)
	}
	if err := store.Backup(backup); err != nil {
		t.Fatal("a second backup replaces the first: ", err)
	}
	if _, err := store.Delete(1); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(backup); err != nil {
		t.Fatal(err)
	}
	if !store.Verify(1, password) {
		t.Fatal("restored account")
	}
	if err := store.Restore(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing backup")
	}
	garbage := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(garbage, []byte(strings.Repeat("not sqlite", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(garbage); err == nil {
		t.Fatal("a bad backup is refused")
	}
	if !store.Verify(1, password) {
		t.Fatal("a bad backup must leave the database alone")
	}
}

func TestCLI(t *testing.T) {
	db := filepath.Join(t.TempDir(), "players.sqlite3")
	run := func(input string, args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := RunCLI(append([]string{"--db", db}, args...), strings.NewReader(input), &out, &errOut)
		return code, out.String() + errOut.String()
	}
	if code, text := run(password+"\n", "add", "5eea2491", "--password-stdin"); code != 0 || !strings.Contains(text, "created: pid 5eea2491") {
		t.Fatal(code, text)
	}
	if code, text := run("bad\n", "add", "5eea2492", "--password-stdin"); code != 1 || !strings.Contains(text, "refused") {
		t.Fatal(code, text)
	}
	if code, text := run("", "list"); code != 0 || !strings.Contains(text, "5eea2491\n") || !strings.Contains(text, "1 account(s)") {
		t.Fatal(code, text)
	}
	if code, text := run("", "ban", "--pid", "5eea2491", "--hours", "2", "--reason", "cheat"); code != 0 || !strings.Contains(text, "banned") {
		t.Fatal(code, text)
	}
	if code, text := run("", "bans"); code != 0 || !strings.Contains(text, "until") || !strings.Contains(text, "cheat") {
		t.Fatal(code, text)
	}
	if code, text := run("", "modlog"); code != 0 || !strings.Contains(text, "ban") {
		t.Fatal(code, text)
	}
	if code, _ := run("", "ban"); code != 2 {
		t.Fatal("ban without a target")
	}
	if code, text := run("", "unban", "--pid", "5eea2491"); code != 0 || !strings.Contains(text, "unbanned") {
		t.Fatal(code, text)
	}
	backup := db + ".bak"
	if code, text := run("", "backup", backup); code != 0 {
		t.Fatal(text)
	}
	if code, text := run("", "delete", "5eea2491"); code != 0 || !strings.Contains(text, "deleted") {
		t.Fatal(code, text)
	}
	if code, text := run("", "delete", "5eea2491"); code != 0 || !strings.Contains(text, "no such account") {
		t.Fatal(code, text)
	}
	if code, text := run("", "restore", backup); code != 0 || !strings.Contains(text, "1 accounts") {
		t.Fatal(code, text)
	}
	if code, _ := run("", "nope"); code != 2 {
		t.Fatal("unknown command")
	}
}

func TestRateLimitIgnoresRowsFromTheOldMonotonicClock(t *testing.T) {
	store := open(t)
	store.MaxAttempts = 2
	if diff := store.Clock() - float64(time.Now().Unix()); diff < -5 || diff > 5 {
		t.Fatalf("not the wall clock: %f", diff)
	}
	if _, err := store.handle().Exec(`INSERT INTO failures (ip, at) VALUES ('203.0.113.9', 90000.0)`); err != nil {
		t.Fatal(err)
	}
	if allowed, err := store.Allow("203.0.113.9"); err != nil || !allowed {
		t.Fatalf("allowed=%t err=%v", allowed, err)
	}
	for i := 0; i < 2; i++ {
		if err := store.Failure("203.0.113.9"); err != nil {
			t.Fatal(err)
		}
	}
	if allowed, err := store.Allow("203.0.113.9"); err != nil || allowed {
		t.Fatalf("allowed=%t err=%v", allowed, err)
	}
}

func TestAnAccountCanBeErased(t *testing.T) {
	store := open(t)
	if _, err := store.Register(0x10000042, password); err != nil {
		t.Fatal(err)
	}
	if erased, err := store.Delete(0x10000042); err != nil || !erased {
		t.Fatalf("erased=%t err=%v", erased, err)
	}
	if key, err := store.Key(0x10000042); err != nil || key != nil {
		t.Fatalf("key=%x err=%v", key, err)
	}
	if erased, err := store.Delete(0x10000042); err != nil || erased {
		t.Fatalf("erased=%t err=%v", erased, err)
	}
}

func TestDatabaseFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "players.sqlite3")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode %o", mode)
	}
}
