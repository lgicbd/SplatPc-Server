package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func public(extra map[string]any) map[string]any {
	values := map[string]any{"mode": "public", "listen": "0.0.0.0", "advertise": "203.0.113.10"}
	for key, value := range extra {
		values[key] = value
	}
	return values
}

func mustNew(t *testing.T, values map[string]any) *Config {
	t.Helper()
	c, err := New(values)
	if err != nil {
		t.Fatalf("New(%v): %v", values, err)
	}
	return c
}

func mustFail(t *testing.T, values map[string]any) {
	t.Helper()
	_, err := New(values)
	var configError *Error
	if !errors.As(err, &configError) {
		t.Fatalf("New(%v): expected a configuration error, got %v", values, err)
	}
}

func TestDefaultsAreTheLabServer(t *testing.T) {
	c := mustNew(t, nil)
	if c.Mode != "lab" || c.Listen != "127.0.0.1" || c.StationHost() != "127.0.0.1" ||
		c.AuthPort != 60000 || c.SecurePort != 60001 || !c.Natcheck || c.HasIdentityRoots || c.IsPublic() {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestPublicDefaults(t *testing.T) {
	c := mustNew(t, public(nil))
	if c.Natcheck || c.SecurePort != 60001 || !c.IsPublic() {
		t.Fatalf("unexpected public defaults: %+v", c)
	}
	if listen := mustNew(t, map[string]any{"mode": "public", "advertise": "203.0.113.10"}).Listen; listen != "0.0.0.0" {
		t.Fatalf("public listens everywhere by default, got %s", listen)
	}
}

func TestRegistrationDefaultsAndValidation(t *testing.T) {
	lab := mustNew(t, nil)
	if lab.Registration != "closed" || lab.RegistrationPort != 0 {
		t.Fatalf("lab registration: %+v", lab)
	}
	c := mustNew(t, public(nil))
	if c.Registration != "closed" || c.RegistrationPort != 0 || c.AccountsDB != "nexlab-accounts.sqlite3" {
		t.Fatalf("public registration: %+v", c)
	}
	mustFail(t, public(map[string]any{"registration": "token"}))
	token := mustNew(t, public(map[string]any{"registration": "token", "registration_token": "s3cret"}))
	if token.Registration != "token" || token.RegistrationPort != 60002 {
		t.Fatalf("token registration: %+v", token)
	}
	mustFail(t, public(map[string]any{"registration": "nope"}))
}

func TestFillTimeout(t *testing.T) {
	if mustNew(t, nil).FillTimeout != 20 || mustNew(t, map[string]any{"fill_timeout": 5}).FillTimeout != 5 {
		t.Fatal("fill_timeout value")
	}
	mustFail(t, map[string]any{"fill_timeout": 0})
	mustFail(t, map[string]any{"fill_timeout": "soon"})
	seconds := 45.0
	c, err := Resolve(Flags{FillTimeout: &seconds})
	if err != nil || c.FillTimeout != 45 {
		t.Fatalf("command line fill_timeout: %v %v", c, err)
	}
}

func TestPublicNatcheckSingleIPNeedsOptIn(t *testing.T) {
	base := map[string]any{"natcheck": true, "natcheck_addresses": []any{"203.0.113.10"}}
	mustFail(t, public(base))
	c := mustNew(t, public(map[string]any{"natcheck": true, "natcheck_addresses": []any{"203.0.113.10"}, "natcheck_single_ip": true}))
	if len(c.NatcheckAddresses) != 1 {
		t.Fatalf("%v", c.NatcheckAddresses)
	}
	mustFail(t, public(map[string]any{"natcheck": true, "natcheck_addresses": []any{"203.0.113.10", "203.0.113.10"}, "natcheck_single_ip": true}))
}

func TestPublicNatcheckNeedsTwoDifferentIPs(t *testing.T) {
	mustFail(t, public(map[string]any{"natcheck": true}))
	mustFail(t, public(map[string]any{"natcheck": true, "natcheck_addresses": []any{"203.0.113.10"}}))
	mustFail(t, public(map[string]any{"natcheck": true, "natcheck_addresses": []any{"203.0.113.10", "203.0.113.10"}}))
	c := mustNew(t, public(map[string]any{"natcheck": true, "natcheck_addresses": []any{"203.0.113.10", "203.0.113.11"}}))
	if len(c.NatcheckAddresses) != 2 {
		t.Fatalf("%v", c.NatcheckAddresses)
	}
	if mustNew(t, nil).NatcheckAddresses != nil {
		t.Fatal("the lab keeps its loopback pair without asking for anything")
	}
}

func TestPublicRefusesLoopback(t *testing.T) {
	mustFail(t, map[string]any{"mode": "public", "listen": "127.0.0.1"})
	mustFail(t, map[string]any{"mode": "public", "listen": "0.0.0.0", "advertise": "127.0.0.1"})
	mustFail(t, map[string]any{"mode": "public", "listen": "0.0.0.0", "advertise": "game.localhost"})
	mustFail(t, public(map[string]any{"natcheck": true, "natcheck_addresses": []any{"127.0.0.1", "203.0.113.11"}}))
}

func TestWildcardListenRequiresAdvertise(t *testing.T) {
	mustFail(t, map[string]any{"mode": "public", "listen": "0.0.0.0"})
	c := mustNew(t, map[string]any{"mode": "public", "listen": "0.0.0.0", "advertise": "srv.example.net"})
	if c.StationHost() != "srv.example.net" {
		t.Fatal(c.StationHost())
	}
}

func TestRejectsBadValues(t *testing.T) {
	for _, values := range []map[string]any{
		{"mode": "nope"},
		{"listen": "not-an-address"},
		{"advertise": "http://example.com"},
		{"auth_port": 0},
		{"auth_port": 70000},
		{"auth_port": 5000, "secure_port": 5000},
		{"natcheck_addresses": []any{"nope"}},
		{"natcheck_addresses": []any{}},
		{"unknown_key": 1},
		{"integrity_mode": "maybe"},
		{"integrity_mode": "enforce"},
		{"integrity_releases": map[string]any{"abc": "0"}},
		{"integrity_releases": map[string]any{"0.1.3": "short"}},
		{"integrity_releases": "nope"},
	} {
		mustFail(t, values)
	}
}

func TestIntegrityReleases(t *testing.T) {
	hash := "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	c := mustNew(t, map[string]any{"integrity_mode": "ENFORCE", "integrity_releases": map[string]any{
		"0.1.3": hash, "0.1.4": []any{hash, hash}}})
	if c.IntegrityMode != "enforce" || len(c.IntegrityReleases["0.1.3"]) != 1 || len(c.IntegrityReleases["0.1.4"]) != 2 {
		t.Fatalf("%+v", c)
	}
	updated, err := c.Updated(map[string]any{"auth_port": 7000})
	if err != nil || len(updated.IntegrityReleases["0.1.4"]) != 2 {
		t.Fatalf("releases survive an update: %v %v", updated, err)
	}
}

func TestMinClientVersion(t *testing.T) {
	if mustNew(t, nil).MinClientVersion != "" {
		t.Fatal("no minimum by default")
	}
	if mustNew(t, map[string]any{"min_client_version": "0.2.0"}).MinClientVersion != "0.2.0" {
		t.Fatal("minimum read")
	}
	for _, bad := range []string{"abc", "1", "1.2.3.4", "v1.0"} {
		mustFail(t, map[string]any{"min_client_version": bad})
	}
}

func TestOptionsOffByDefault(t *testing.T) {
	if mustNew(t, nil).RegistrationProxy || !mustNew(t, map[string]any{"registration_proxy": true}).RegistrationProxy {
		t.Fatal("registration_proxy")
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadIgnoresCommentKeysAndBOM(t *testing.T) {
	c, err := Load(writeFile(t, "\xef\xbb\xbf"+`{"_help": "notes", "mode": "public", "listen": "0.0.0.0", "advertise": "203.0.113.10", "auth_port": 7000}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "public" || c.AuthPort != 7000 || c.SecurePort != 7001 || c.StationHost() != "203.0.113.10" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadErrors(t *testing.T) {
	for _, path := range []string{filepath.Join(t.TempDir(), "missing.json"), writeFile(t, `{"mode": `), writeFile(t, `[1]`)} {
		var configError *Error
		if _, err := Load(path); !errors.As(err, &configError) {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func TestExampleFileLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "deploy", "server.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "lab" || c.AuthPort != 60000 {
		t.Fatalf("%+v", c)
	}
}

func TestUpdatedKeepsTheRest(t *testing.T) {
	c := mustNew(t, public(map[string]any{"auth_port": 7000, "natcheck_addresses": []any{"203.0.113.10"}}))
	pushed, err := c.Updated(map[string]any{"auth_port": 7100, "identities": []string{"a.ini"}})
	if err != nil {
		t.Fatal(err)
	}
	if pushed.Mode != "public" || pushed.AuthPort != 7100 || len(pushed.Identities) != 1 ||
		pushed.NatcheckAddresses[0] != "203.0.113.10" || pushed.Advertise != "203.0.113.10" {
		t.Fatalf("%+v", pushed)
	}
}

func TestCommandLine(t *testing.T) {
	c, err := Resolve(Flags{})
	if err != nil || c.Mode != "lab" || c.Listen != "127.0.0.1" || c.AuthPort != 60000 || !c.Natcheck {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	port := 7100
	if c, err = Resolve(Flags{Port: &port}); err != nil || c.AuthPort != 7100 || c.SecurePort != 7101 {
		t.Fatalf("--port moves the pair: %+v %v", c, err)
	}
	port = 7200
	c, err = Resolve(Flags{Public: true, Port: &port, Advertise: "203.0.113.10"})
	if err != nil || c.Mode != "public" || c.AuthPort != 7200 || c.SecurePort != 7201 {
		t.Fatalf("--public: %+v %v", c, err)
	}
	if c.Natcheck || c.Listen != "0.0.0.0" {
		t.Fatalf("--public must not drag the lab's defaults along: %+v", c)
	}
	if _, err = Resolve(Flags{Public: true, Mode: "lab"}); err == nil {
		t.Fatal("--public contradicts --mode lab")
	}
	off := false
	if c, err = Resolve(Flags{Natcheck: &off}); err != nil || c.Natcheck {
		t.Fatalf("--no-natcheck: %+v %v", c, err)
	}
	if c, err = Resolve(Flags{NatcheckAddresses: []string{"203.0.113.10"}}); err != nil || c.NatcheckAddresses[0] != "203.0.113.10" {
		t.Fatalf("--natcheck-address: %+v %v", c, err)
	}
	registrationPort := 60080
	c, err = Resolve(Flags{Public: true, Registration: "token", RegistrationToken: "abc", AccountsDB: "players.sqlite3",
		RegistrationPort: &registrationPort, Advertise: "203.0.113.10"})
	if err != nil || c.Registration != "token" || c.RegistrationPort != 60080 || c.AccountsDB != "players.sqlite3" || c.RegistrationToken != "abc" {
		t.Fatalf("registration flags: %+v %v", c, err)
	}
}

func TestCommandLineOverridesAFile(t *testing.T) {
	path := writeFile(t, `{"mode": "lab", "listen": "0.0.0.0", "advertise": "203.0.113.10", "auth_port": 7000}`)
	c, err := Resolve(Flags{ConfigFile: path, Public: true})
	if err != nil || c.Mode != "public" || c.AuthPort != 7000 || c.Listen != "0.0.0.0" {
		t.Fatalf("%+v %v", c, err)
	}
}
