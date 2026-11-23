// Package wireguard manages the server's WireGuard interface, peer lifecycle,
// and iptables P2P / ban rules for Splatoon PC online play.
package wireguard

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lgicbd/SplatPc-Server/internal/logx"
)

const (
	BanChain     = "SPLAT_WG_BAN"
	ForwardChain = "SPLAT_WG_FWD"
)

// Runner executes external commands (wg, iptables, ip). Mocked in unit tests.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Config holds the WireGuard P2P server settings.
type Config struct {
	Interface      string
	Endpoint       string
	Subnet         netip.Prefix
	ServerIP       netip.Addr
	ListenPort     int
	PrivateKeyFile string
	EnableIPTables bool
	MTU            int
	Keepalive      int
}

// Manager drives the WireGuard interface and iptables rules.
type Manager struct {
	cfg       Config
	runner    Runner
	mu        sync.Mutex
	publicKey string
}

// New creates a Manager. If runner is nil, the system OS exec runner is used.
func New(cfg Config, runner Runner) *Manager {
	if runner == nil {
		runner = execRunner{}
	}
	if cfg.Interface == "" {
		cfg.Interface = "wg0"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	if cfg.Keepalive == 0 {
		cfg.Keepalive = 25
	}
	return &Manager{cfg: cfg, runner: runner}
}

// Config returns a copy of the manager's configuration.
func (m *Manager) Config() Config { return m.cfg }

// ServerPublicKey returns the base64-encoded WireGuard public key of the server.
func (m *Manager) ServerPublicKey() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publicKey
}

// GenerateKeypair generates a fresh WireGuard X25519 keypair (base64 private, base64 public).
func GenerateKeypair() (string, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// ValidatePublicKey verifies that a string is a valid base64-encoded 32-byte X25519 key.
func ValidatePublicKey(pubB64 string) (string, error) {
	trimmed := strings.TrimSpace(pubB64)
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid WireGuard public key (expected base64 32-byte key)")
	}
	if _, err := ecdh.X25519().NewPublicKey(raw); err != nil {
		return "", errors.New("invalid WireGuard public key")
	}
	return trimmed, nil
}

func publicKeyFromPrivate(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid WireGuard private key")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// EnsureSetup loads/creates the server private key, configures the WireGuard interface,
// and installs the base iptables P2P and ban chains when enabled.
func (m *Manager) EnsureSetup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	privKeyPath := m.cfg.PrivateKeyFile
	if privKeyPath != "" {
		privB64, err := m.loadOrCreatePrivateKey(privKeyPath)
		if err != nil {
			return fmt.Errorf("wireguard key: %w", err)
		}
		pubB64, err := publicKeyFromPrivate(privB64)
		if err != nil {
			return fmt.Errorf("wireguard public key: %w", err)
		}
		m.publicKey = pubB64

		if _, err := m.runner.Run("wg", "set", m.cfg.Interface,
			"listen-port", fmt.Sprint(m.cfg.ListenPort),
			"private-key", privKeyPath); err != nil {
			return fmt.Errorf("wg set %s: %w", m.cfg.Interface, err)
		}
	} else {
		out, err := m.runner.Run("wg", "show", m.cfg.Interface, "public-key")
		if err != nil {
			return fmt.Errorf("wg show %s public-key: %w", m.cfg.Interface, err)
		}
		m.publicKey = strings.TrimSpace(string(out))
	}

	if m.cfg.EnableIPTables {
		if err := m.setupIPTablesLocked(); err != nil {
			return fmt.Errorf("iptables setup: %w", err)
		}
	}
	logx.Infof("wireguard: interface=%s endpoint=%s subnet=%s server_ip=%s pubkey=%s",
		m.cfg.Interface, m.cfg.Endpoint, m.cfg.Subnet, m.cfg.ServerIP, m.publicKey)
	return nil
}

func (m *Manager) loadOrCreatePrivateKey(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
		if _, err := publicKeyFromPrivate(key); err == nil {
			return key, nil
		}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	privB64, _, err := GenerateKeypair()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(privB64+"\n"), 0o600); err != nil {
		return "", err
	}
	return privB64, nil
}

func (m *Manager) setupIPTablesLocked() error {
	iface := m.cfg.Interface
	// Ensure custom chains exist (ignore error if they already exist).
	_, _ = m.runner.Run("iptables", "-N", BanChain)
	_, _ = m.runner.Run("iptables", "-N", ForwardChain)

	// Rebuild ForwardChain atomically-enough: flush then append rules.
	if _, err := m.runner.Run("iptables", "-F", ForwardChain); err != nil {
		return err
	}
	rules := [][]string{
		{"-A", ForwardChain, "-i", iface, "-j", BanChain},
		{"-A", ForwardChain, "-o", iface, "-j", BanChain},
		{"-A", ForwardChain, "-i", iface, "-o", iface, "-p", "udp", "-j", "ACCEPT"},
		{"-A", ForwardChain, "-i", iface, "-o", iface, "-p", "icmp", "-j", "ACCEPT"},
		{"-A", ForwardChain, "-i", iface, "-o", iface, "-j", "DROP"},
		{"-A", ForwardChain, "-i", iface, "!", "-o", iface, "-j", "DROP"},
	}
	for _, r := range rules {
		if _, err := m.runner.Run("iptables", r...); err != nil {
			return err
		}
	}

	if err := m.ensureJumpLocked("FORWARD", "-j", ForwardChain); err != nil {
		return err
	}
	if err := m.ensureJumpLocked("INPUT", "-i", iface, "-j", BanChain); err != nil {
		return err
	}
	return nil
}

func (m *Manager) ensureJumpLocked(chain string, spec ...string) error {
	checkArgs := append([]string{"-C", chain}, spec...)
	if _, err := m.runner.Run("iptables", checkArgs...); err == nil {
		return nil
	}
	insertArgs := append([]string{"-I", chain, "1"}, spec...)
	_, err := m.runner.Run("iptables", insertArgs...)
	return err
}

// AllowPeer adds or updates a WireGuard peer and clears any iptables ban rule for its IP.
func (m *Manager) AllowPeer(publicKey, assignedIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.EnableIPTables && assignedIP != "" {
		m.unbanIPLocked(assignedIP)
	}
	if _, err := m.runner.Run("wg", "set", m.cfg.Interface,
		"peer", publicKey, "allowed-ips", assignedIP+"/32"); err != nil {
		return fmt.Errorf("wg add peer: %w", err)
	}
	return nil
}

// BanPeer removes a WireGuard peer from the interface and drops its virtual IP in iptables.
func (m *Manager) BanPeer(publicKey, assignedIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if publicKey != "" {
		if _, err := m.runner.Run("wg", "set", m.cfg.Interface,
			"peer", publicKey, "remove"); err != nil {
			logx.Warnf("wireguard: remove peer %s: %v", publicKey, err)
		}
	}
	if m.cfg.EnableIPTables && assignedIP != "" {
		return m.banIPLocked(assignedIP)
	}
	return nil
}

// UnbanIP removes iptables drop rules for a peer's virtual IP.
func (m *Manager) UnbanIP(assignedIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.EnableIPTables && assignedIP != "" {
		m.unbanIPLocked(assignedIP)
	}
}

// FlushBans clears all rules in SPLAT_WG_BAN.
func (m *Manager) FlushBans() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.EnableIPTables {
		return nil
	}
	_, err := m.runner.Run("iptables", "-F", BanChain)
	return err
}

func (m *Manager) banIPLocked(ip string) error {
	cidr := ip + "/32"
	for _, dir := range []string{"-s", "-d"} {
		if _, err := m.runner.Run("iptables", "-C", BanChain, dir, cidr, "-j", "DROP"); err != nil {
			if _, err := m.runner.Run("iptables", "-A", BanChain, dir, cidr, "-j", "DROP"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) unbanIPLocked(ip string) {
	cidr := ip + "/32"
	for _, dir := range []string{"-s", "-d"} {
		for i := 0; i < 32; i++ {
			if _, err := m.runner.Run("iptables", "-D", BanChain, dir, cidr, "-j", "DROP"); err != nil {
				break
			}
		}
	}
}
