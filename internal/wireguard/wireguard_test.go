package wireguard

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordedCall struct {
	name string
	args []string
}

type fakeRunner struct {
	calls []recordedCall
	fail  map[string]error
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, recordedCall{name: name, args: append([]string(nil), args...)})
	key := name + " " + strings.Join(args, " ")
	if err, ok := f.fail[key]; ok {
		return nil, err
	}
	return nil, nil
}

func (f *fakeRunner) hasCall(prefix string) bool {
	for _, c := range f.calls {
		full := c.name + " " + strings.Join(c.args, " ")
		if strings.HasPrefix(full, prefix) {
			return true
		}
	}
	return false
}

func TestGenerateAndValidateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if priv == "" || pub == "" || priv == pub {
		t.Fatalf("unexpected keypair: priv=%q pub=%q", priv, pub)
	}
	gotPub, err := ValidatePublicKey("  " + pub + "\n")
	if err != nil || gotPub != pub {
		t.Fatalf("ValidatePublicKey: got %q, err=%v", gotPub, err)
	}
	if _, err := ValidatePublicKey("not-a-key"); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestEnsureSetupAndPeerLifecycle(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "wg_private.key")
	runner := &fakeRunner{
		fail: map[string]error{
			"iptables -C FORWARD -j SPLAT_WG_FWD":          errors.New("not found"),
			"iptables -C INPUT -i wg0 -j SPLAT_WG_BAN":     errors.New("not found"),
			"iptables -C SPLAT_WG_BAN -s 10.66.0.2/32 -j DROP": errors.New("not found"),
			"iptables -C SPLAT_WG_BAN -d 10.66.0.2/32 -j DROP": errors.New("not found"),
			"iptables -D SPLAT_WG_BAN -s 10.66.0.2/32 -j DROP": errors.New("not found"),
			"iptables -D SPLAT_WG_BAN -d 10.66.0.2/32 -j DROP": errors.New("not found"),
		},
	}

	mgr := New(Config{
		Interface:      "wg0",
		Endpoint:       "203.0.113.10:51820",
		Subnet:         netip.MustParsePrefix("10.66.0.0/16"),
		ServerIP:       netip.MustParseAddr("10.66.0.1"),
		ListenPort:     51820,
		PrivateKeyFile: keyFile,
		EnableIPTables: true,
	}, runner)

	if err := mgr.EnsureSetup(); err != nil {
		t.Fatalf("EnsureSetup: %v", err)
	}
	if mgr.ServerPublicKey() == "" {
		t.Fatal("ServerPublicKey is empty")
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("keyFile not created: %v", err)
	}
	if !runner.hasCall("wg set wg0 listen-port 51820 private-key " + keyFile) {
		t.Fatalf("missing wg set call: %+v", runner.calls)
	}
	if !runner.hasCall("iptables -A SPLAT_WG_FWD -i wg0 -o wg0 -p udp -j ACCEPT") {
		t.Fatalf("missing P2P UDP accept rule")
	}
	if !runner.hasCall("iptables -I FORWARD 1 -j SPLAT_WG_FWD") {
		t.Fatalf("missing FORWARD jump")
	}

	_, clientPub, _ := GenerateKeypair()
	if err := mgr.AllowPeer(clientPub, "10.66.0.2"); err != nil {
		t.Fatalf("AllowPeer: %v", err)
	}
	if !runner.hasCall("wg set wg0 peer " + clientPub + " allowed-ips 10.66.0.2/32") {
		t.Fatalf("missing wg set peer call")
	}

	if err := mgr.BanPeer(clientPub, "10.66.0.2"); err != nil {
		t.Fatalf("BanPeer: %v", err)
	}
	if !runner.hasCall("wg set wg0 peer " + clientPub + " remove") {
		t.Fatalf("missing wg remove peer call")
	}
	if !runner.hasCall("iptables -A SPLAT_WG_BAN -s 10.66.0.2/32 -j DROP") {
		t.Fatalf("missing iptables ban -s rule")
	}
	if !runner.hasCall("iptables -A SPLAT_WG_BAN -d 10.66.0.2/32 -j DROP") {
		t.Fatalf("missing iptables ban -d rule")
	}
}
