package accounts

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func TestAssignWGPeer(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	subnet := netip.MustParsePrefix("10.66.0.0/16")
	serverIP := netip.MustParseAddr("10.66.0.1")

	p1, err := store.AssignWGPeer(0x10000001, "pubA", subnet, serverIP)
	if err != nil {
		t.Fatalf("AssignWGPeer 1: %v", err)
	}
	if p1.AssignedIP != "10.66.0.2" {
		t.Fatalf("expected 10.66.0.2, got %s", p1.AssignedIP)
	}

	p2, err := store.AssignWGPeer(0x10000002, "pubB", subnet, serverIP)
	if err != nil {
		t.Fatalf("AssignWGPeer 2: %v", err)
	}
	if p2.AssignedIP != "10.66.0.3" {
		t.Fatalf("expected 10.66.0.3, got %s", p2.AssignedIP)
	}

	// Rotating public key for same PID keeps assigned IP.
	p1Rot, err := store.AssignWGPeer(0x10000001, "pubA2", subnet, serverIP)
	if err != nil {
		t.Fatalf("AssignWGPeer rotate: %v", err)
	}
	if p1Rot.AssignedIP != "10.66.0.2" || p1Rot.PublicKey != "pubA2" {
		t.Fatalf("unexpected rotation result: %+v", p1Rot)
	}

	// Duplicate public key across accounts is refused.
	if _, err := store.AssignWGPeer(0x10000003, "pubB", subnet, serverIP); !IsInvalidIdentity(err) {
		t.Fatalf("expected InvalidIdentityError for duplicate key, got %v", err)
	}
}
