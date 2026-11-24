package accounts

import (
	"database/sql"
	"errors"
	"net/netip"
	"strings"
)

const createWGPeers = `CREATE TABLE IF NOT EXISTS wg_peers (
	pid INTEGER PRIMARY KEY,
	public_key TEXT NOT NULL UNIQUE,
	assigned_ip TEXT NOT NULL UNIQUE,
	created REAL NOT NULL,
	updated REAL NOT NULL
)`

// WGPeer is one player's WireGuard P2P allocation.
type WGPeer struct {
	PID        uint32
	PublicKey  string
	AssignedIP string
	Created    float64
	Updated    float64
}

// AssignWGPeer allocates (or updates the public key of) a WireGuard IP for pid inside subnet.
func (s *Store) AssignWGPeer(pid uint32, publicKey string, subnet netip.Prefix, reserved ...netip.Addr) (WGPeer, error) {
	if pid == 0 || pid > MaxPID {
		return WGPeer{}, invalid("pid must be in 1..0x7fffffff")
	}
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return WGPeer{}, invalid("wireguard public_key is required")
	}
	subnet = subnet.Masked()
	if !subnet.IsValid() || !subnet.Addr().Is4() {
		return WGPeer{}, errors.New("invalid IPv4 WireGuard subnet")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return WGPeer{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var owner uint32
	err = tx.QueryRow(`SELECT pid FROM wg_peers WHERE public_key = ?`, publicKey).Scan(&owner)
	if err == nil && owner != pid {
		return WGPeer{}, invalid("this WireGuard public key is already registered to another account")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return WGPeer{}, err
	}

	now := s.Clock()
	var existing WGPeer
	err = tx.QueryRow(`SELECT pid, public_key, assigned_ip, created, updated FROM wg_peers WHERE pid = ?`, pid).
		Scan(&existing.PID, &existing.PublicKey, &existing.AssignedIP, &existing.Created, &existing.Updated)
	if err == nil {
		if existing.PublicKey != publicKey {
			if _, err := tx.Exec(`UPDATE wg_peers SET public_key = ?, updated = ? WHERE pid = ?`,
				publicKey, now, pid); err != nil {
				return WGPeer{}, err
			}
			existing.PublicKey = publicKey
		} else {
			if _, err := tx.Exec(`UPDATE wg_peers SET updated = ? WHERE pid = ?`, now, pid); err != nil {
				return WGPeer{}, err
			}
		}
		existing.Updated = now
		if err := tx.Commit(); err != nil {
			return WGPeer{}, err
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return WGPeer{}, err
	}

	used := map[netip.Addr]bool{}
	for _, r := range reserved {
		if r.IsValid() {
			used[r] = true
		}
	}
	rows, err := tx.Query(`SELECT assigned_ip FROM wg_peers`)
	if err != nil {
		return WGPeer{}, err
	}
	for rows.Next() {
		var ipStr string
		if err := rows.Scan(&ipStr); err != nil {
			rows.Close()
			return WGPeer{}, err
		}
		if addr, err := netip.ParseAddr(ipStr); err == nil {
			used[addr] = true
		}
	}
	rows.Close()

	assigned, ok := nextFreeIPv4(subnet, used)
	if !ok {
		return WGPeer{}, errors.New("wireguard subnet has no free IP addresses")
	}

	peer := WGPeer{
		PID:        pid,
		PublicKey:  publicKey,
		AssignedIP: assigned.String(),
		Created:    now,
		Updated:    now,
	}
	if _, err := tx.Exec(`INSERT INTO wg_peers(pid, public_key, assigned_ip, created, updated) VALUES (?, ?, ?, ?, ?)`,
		peer.PID, peer.PublicKey, peer.AssignedIP, peer.Created, peer.Updated); err != nil {
		return WGPeer{}, err
	}
	if err := tx.Commit(); err != nil {
		return WGPeer{}, err
	}
	return peer, nil
}

func nextFreeIPv4(subnet netip.Prefix, used map[netip.Addr]bool) (netip.Addr, bool) {
	network := subnet.Addr().As4()
	base := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
	hostBits := 32 - subnet.Bits()
	if hostBits < 2 {
		return netip.Addr{}, false
	}
	total := uint64(1) << hostBits
	// Skip network address (0) and broadcast address (total-1).
	for offset := uint64(1); offset < total-1; offset++ {
		ipInt := base + uint32(offset)
		addr := netip.AddrFrom4([4]byte{byte(ipInt >> 24), byte(ipInt >> 16), byte(ipInt >> 8), byte(ipInt)})
		if !used[addr] {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// GetWGPeer returns the WireGuard peer assigned to pid, or nil when none exists.
func (s *Store) GetWGPeer(pid uint32) (*WGPeer, error) {
	var peer WGPeer
	err := s.handle().QueryRow(`SELECT pid, public_key, assigned_ip, created, updated FROM wg_peers WHERE pid = ?`, pid).
		Scan(&peer.PID, &peer.PublicKey, &peer.AssignedIP, &peer.Created, &peer.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &peer, nil
}

// ListWGPeers returns all registered WireGuard peers.
func (s *Store) ListWGPeers() ([]WGPeer, error) {
	rows, err := s.handle().Query(`SELECT pid, public_key, assigned_ip, created, updated FROM wg_peers ORDER BY pid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var peers []WGPeer
	for rows.Next() {
		var p WGPeer
		if err := rows.Scan(&p.PID, &p.PublicKey, &p.AssignedIP, &p.Created, &p.Updated); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}
