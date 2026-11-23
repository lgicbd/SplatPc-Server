package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/social"
	"github.com/lgicbd/SplatPc-Server/internal/wireguard"
)

type stubRunner struct {
	calls []string
	rules map[string]bool
}

func (r *stubRunner) Run(name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	if r.rules == nil {
		r.rules = map[string]bool{}
	}
	if name == "iptables" && len(args) >= 2 {
		key := strings.Join(args[1:], " ")
		switch args[0] {
		case "-C":
			if !r.rules[key] {
				return nil, errNotFound
			}
		case "-A":
			r.rules[key] = true
		case "-D":
			if !r.rules[key] {
				return nil, errNotFound
			}
			delete(r.rules, key)
		}
	}
	return nil, nil
}

var errNotFound = &accounts.InvalidIdentityError{Message: "not found"}

func (r *stubRunner) has(prefix string) bool {
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

type noopLive struct{}

func (noopLive) Stats() Stats            { return Stats{} }
func (noopLive) Errors() uint64          { return 0 }
func (noopLive) Sessions() []SessionInfo { return nil }
func (noopLive) ActivePlayers() []uint32 { return nil }
func (noopLive) RequestKick(uint32)      {}

func TestWGKeyEndpointAndBanLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := accounts.Open(filepath.Join(dir, "accounts.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const pid uint32 = 0x10001234
	const pass = "Abcd1234Efgh5678"
	if _, err := store.Register(pid, pass); err != nil {
		t.Fatal(err)
	}

	runner := &stubRunner{}
	wgMgr := wireguard.New(wireguard.Config{
		Interface:      "wg0",
		Endpoint:       "203.0.113.10:51820",
		Subnet:         netip.MustParsePrefix("10.66.0.0/16"),
		ServerIP:       netip.MustParseAddr("10.66.0.1"),
		ListenPort:     51820,
		PrivateKeyFile: filepath.Join(dir, "wg.key"),
		EnableIPTables: true,
	}, runner)
	if err := wgMgr.EnsureSetup(); err != nil {
		t.Fatal(err)
	}

	soc := social.New(store, nil, "off", nil)
	token, err := soc.OpenSession(pid, pass, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		Accounts:   store,
		Social:     soc,
		Live:       noopLive{},
		WG:         wgMgr,
		AdminToken: "secret-admin",
	})

	_, clientPub, _ := wireguard.GenerateKeypair()
	body, _ := json.Marshal(map[string]any{"token": token, "public_key": clientPub})
	req := httptest.NewRequest(http.MethodPost, "/social/wg", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /social/wg: status=%d body=%s", rec.Code, rec.Body.String())
	}

	var wgResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &wgResp); err != nil {
		t.Fatal(err)
	}
	if wgResp["client_ip"] != "10.66.0.2" || wgResp["endpoint"] != "203.0.113.10:51820" {
		t.Fatalf("unexpected wg response: %+v", wgResp)
	}
	if !runner.has("wg set wg0 peer " + clientPub + " allowed-ips 10.66.0.2/32") {
		t.Fatalf("expected wg set peer call, got %v", runner.calls)
	}

	// Ban the player via /admin/ban -> removes WG peer and adds iptables drop.
	banBody, _ := json.Marshal(map[string]any{"pid": "0x10001234", "reason": "cheat"})
	banReq := httptest.NewRequest(http.MethodPost, "/admin/ban", bytes.NewReader(banBody))
	banReq.ContentLength = int64(len(banBody))
	banReq.Header.Set("Authorization", "Bearer secret-admin")
	banRec := httptest.NewRecorder()
	srv.ServeHTTP(banRec, banReq)
	if banRec.Code != http.StatusOK {
		t.Fatalf("POST /admin/ban: status=%d body=%s", banRec.Code, banRec.Body.String())
	}
	if !runner.has("wg set wg0 peer " + clientPub + " remove") {
		t.Fatalf("expected wg remove peer on ban, got %v", runner.calls)
	}
	if !runner.has("iptables -A SPLAT_WG_BAN -s 10.66.0.2/32 -j DROP") {
		t.Fatalf("expected iptables ban on ban, got %v", runner.calls)
	}

	// Banned player cannot request a new WG key even with credentials.
	credBody, _ := json.Marshal(map[string]any{"pid": "0x10001234", "password": pass})
	credReq := httptest.NewRequest(http.MethodPost, "/social/wg", bytes.NewReader(credBody))
	credReq.ContentLength = int64(len(credBody))
	credRec := httptest.NewRecorder()
	srv.ServeHTTP(credRec, credReq)
	if credRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for banned player, got %d (%s)", credRec.Code, credRec.Body.String())
	}

	// Unban the player via /admin/unban -> clears iptables drop.
	unbanBody, _ := json.Marshal(map[string]any{"pid": "0x10001234"})
	unbanReq := httptest.NewRequest(http.MethodPost, "/admin/unban", bytes.NewReader(unbanBody))
	unbanReq.ContentLength = int64(len(unbanBody))
	unbanReq.Header.Set("Authorization", "Bearer secret-admin")
	unbanRec := httptest.NewRecorder()
	srv.ServeHTTP(unbanRec, unbanReq)
	if unbanRec.Code != http.StatusOK {
		t.Fatalf("POST /admin/unban: status=%d body=%s", unbanRec.Code, unbanRec.Body.String())
	}
	if !runner.has("iptables -D SPLAT_WG_BAN -s 10.66.0.2/32 -j DROP") {
		t.Fatalf("expected iptables unban, got %v", runner.calls)
	}
}
