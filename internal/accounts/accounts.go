// Package accounts is the account store of the public server. A player is identified by the
// 31-bit PID its port generated. The game never transmits its 16-character NEX password, so a
// player registers once and the server keeps only the derived Kerberos key: no plaintext password,
// no secret in any log line. The file format is shared with the former Python server.
package accounts

import (
	"crypto/md5"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver
)

const (
	MaxPID          = 0x7FFFFFFF
	defaultAttempts = 10
	defaultWindow   = 300.0
	maxReason       = 200
	maxModLogRows   = 2000
)

// InvalidIdentityError is a refused pid, password, address or ban; the message is safe to show.
type InvalidIdentityError struct{ Message string }

func (e *InvalidIdentityError) Error() string { return e.Message }

// AlreadyRegisteredError means the pid belongs to another key.
type AlreadyRegisteredError struct{ Message string }

func (e *AlreadyRegisteredError) Error() string { return e.Message }

func invalid(message string) error { return &InvalidIdentityError{message} }

// IsInvalidIdentity tells a refused identity from a storage failure.
func IsInvalidIdentity(err error) bool {
	var target *InvalidIdentityError
	return errors.As(err, &target)
}

// DeriveKey is the Kerberos key the NEX ticket is encrypted with (same derivation as the game).
func DeriveKey(password string, pid uint32) []byte {
	sum := md5.Sum([]byte(password))
	for i := uint32(1); i < 65000+pid%1024; i++ {
		sum = md5.Sum(sum[:])
	}
	return sum[:]
}

// ParsePID reads decimal, 0x-hexadecimal or bare hexadecimal ('5eea2491', as online_identity.ini
// writes it), in 1..0x7fffffff.
func ParsePID(value string) (uint32, error) {
	text := strings.ToLower(strings.TrimSpace(value))
	var (
		number uint64
		err    error
	)
	if digits, isHex := strings.CutPrefix(text, "0x"); isHex {
		number, err = strconv.ParseUint(digits, 16, 64)
	} else {
		number, err = strconv.ParseUint(strings.TrimPrefix(text, "+"), 10, 64)
		if isSyntaxError(err) {
			number, err = strconv.ParseUint(text, 16, 64)
		}
	}
	if isSyntaxError(err) {
		return 0, invalid("pid must be decimal or hexadecimal")
	}
	if err != nil || number == 0 || number > MaxPID {
		return 0, invalid("pid must be in 1..0x7fffffff")
	}
	return uint32(number), nil
}

func isSyntaxError(err error) bool { return errors.Is(err, strconv.ErrSyntax) }

// CheckPassword refuses anything but 16 ASCII letters or digits.
func CheckPassword(password string) error {
	valid := len(password) == 16
	for i := 0; valid && i < len(password); i++ {
		c := password[i]
		valid = c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	if !valid {
		return invalid("the NEX password must be 16 letters or digits")
	}
	return nil
}

// IPKey is the canonical key of a source address. IPv6 is grouped by /64: one home gets a whole
// /64, so a limit on single IPv6 addresses would never bind. Text that is no address is "unknown".
func IPKey(value string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "unknown"
	}
	address = address.WithZone("").Unmap()
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().Addr().String() + "/64"
	}
	return address.String()
}

// Store is the SQLite account database: one row per pid, holding the derived key, never the
// password. A single connection serializes every access.
type Store struct {
	Path        string
	MaxAttempts int
	Window      float64
	Clock       func() float64

	mu sync.RWMutex // Restore swaps db
	db *sql.DB
}

// Open creates the file and its tables as needed.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	store := &Store{Path: path, MaxAttempts: defaultAttempts, Window: defaultWindow, Clock: Now}
	if err := store.connect(); err != nil {
		return nil, err
	}
	store.restrictPermissions()
	return store, nil
}

// Now is the wall clock in seconds, as stored in the database.
func Now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (s *Store) connect() error {
	// WAL + NORMAL: no fsync per login, still no corruption.
	db, err := sql.Open("sqlite", s.Path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	if err := createSchema(db); err != nil {
		db.Close()
		return fmt.Errorf("%s: %w", s.Path, err)
	}
	s.db = db
	return nil
}

func createSchema(db *sql.DB) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS accounts (pid INTEGER PRIMARY KEY, key BLOB NOT NULL, created REAL NOT NULL, last_seen REAL)`,
		`CREATE TABLE IF NOT EXISTS failures (ip TEXT NOT NULL, at REAL NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS failures_ip_at ON failures(ip, at)`,
		`CREATE TABLE IF NOT EXISTS pseudos (pid INTEGER PRIMARY KEY, pseudo TEXT NOT NULL, pkey TEXT NOT NULL UNIQUE)`,
		`CREATE TABLE IF NOT EXISTS bans (pid INTEGER, ip TEXT, reason TEXT, created REAL NOT NULL, UNIQUE(pid, ip))`,
		`CREATE TABLE IF NOT EXISTS mod_log (at REAL NOT NULL, action TEXT NOT NULL, pid INTEGER, ip TEXT, detail TEXT)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	var present int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('bans') WHERE name = 'expires'`).Scan(&present); err != nil {
		return err
	}
	if present == 0 {
		if _, err := db.Exec(`ALTER TABLE bans ADD COLUMN expires REAL`); err != nil { // NULL: permanent
			return err
		}
	}
	return nil
}

// restrictPermissions keeps the file private: it holds Kerberos keys, i.e. credentials.
func (s *Store) restrictPermissions() {
	for _, path := range []string{s.Path, s.Path + "-wal", s.Path + "-shm"} {
		_ = os.Chmod(path, 0o600) // Windows, or a filesystem without POSIX modes: nothing to do
	}
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

func (s *Store) handle() *sql.DB {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db
}

// Backup copies the database to a file, replacing it.
func (s *Store) Backup(destination string) error {
	removeDatabase(destination)
	if _, err := s.handle().Exec(`VACUUM INTO ?`, destination); err != nil {
		return err
	}
	_ = os.Chmod(destination, 0o600)
	return nil
}

// Restore replaces this database with a backup (stop the server first).
func (s *Store) Restore(source string) error {
	if info, err := os.Stat(source); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("no such backup: %s", source)
	}
	backup, err := sql.Open("sqlite", source)
	if err != nil {
		return err
	}
	defer backup.Close()
	staged := s.Path + ".restoring"
	removeDatabase(staged)
	if _, err := backup.Exec(`VACUUM INTO ?`, staged); err != nil { // a bad backup leaves the database alone
		removeDatabase(staged)
		return fmt.Errorf("%s: %w", source, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.db.Close(); err != nil {
		return err
	}
	removeDatabase(s.Path)
	if err := os.Rename(staged, s.Path); err != nil {
		return err
	}
	if err := s.connect(); err != nil {
		return err
	}
	s.restrictPermissions()
	return nil
}

func removeDatabase(path string) {
	for _, target := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Remove(target)
	}
}

func (s *Store) Count() (int, error) {
	var count int
	err := s.handle().QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&count)
	return count, err
}

func (s *Store) PIDs() ([]uint32, error) {
	rows, err := s.handle().Query(`SELECT pid FROM accounts ORDER BY pid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pids []uint32
	for rows.Next() {
		var pid uint32
		if err := rows.Scan(&pid); err != nil {
			return nil, err
		}
		pids = append(pids, pid)
	}
	return pids, rows.Err()
}

// Key is the stored Kerberos key, nil for an unknown pid.
func (s *Store) Key(pid uint32) ([]byte, error) {
	var key []byte
	err := s.handle().QueryRow(`SELECT key FROM accounts WHERE pid = ?`, pid).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return key, err
}

func (s *Store) Touch(pid uint32) error {
	_, err := s.handle().Exec(`UPDATE accounts SET last_seen = ? WHERE pid = ?`, Now(), pid)
	return err
}

// Delete erases one account (a player's request to be forgotten); true when it existed.
func (s *Store) Delete(pid uint32) (bool, error) {
	result, err := s.handle().Exec(`DELETE FROM accounts WHERE pid = ?`, pid)
	if err != nil {
		return false, err
	}
	removed, err := result.RowsAffected()
	return removed > 0, err
}

// ClaimPseudo gives the pseudo to this account; false when another account has it. Pseudos are
// unique ignoring case.
func (s *Store) ClaimPseudo(pid uint32, pseudo string) (bool, error) {
	pseudo = strings.TrimSpace(pseudo)
	result, err := s.handle().Exec(`INSERT INTO pseudos (pid, pseudo, pkey) VALUES (?, ?, ?)
		ON CONFLICT(pid) DO UPDATE SET pseudo = excluded.pseudo, pkey = excluded.pkey
		ON CONFLICT(pkey) DO UPDATE SET pseudo = excluded.pseudo WHERE pseudos.pid = excluded.pid`,
		pid, pseudo, strings.ToLower(pseudo))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return false, nil
		}
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed > 0, err
}

// PseudoOf is the account's pseudo, "" when it has none.
func (s *Store) PseudoOf(pid uint32) (string, error) {
	var pseudo string
	err := s.handle().QueryRow(`SELECT pseudo FROM pseudos WHERE pid = ?`, pid).Scan(&pseudo)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return pseudo, err
}

// PIDForPseudo is 0 when nobody has this pseudo.
func (s *Store) PIDForPseudo(pseudo string) (uint32, error) {
	var pid uint32
	err := s.handle().QueryRow(`SELECT pid FROM pseudos WHERE pkey = ?`, strings.ToLower(strings.TrimSpace(pseudo))).Scan(&pid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return pid, err
}

// PseudosFor maps each listed pid that has a pseudo to it.
func (s *Store) PseudosFor(pids []uint32) (map[uint32]string, error) {
	names := map[uint32]string{}
	if len(pids) == 0 {
		return names, nil
	}
	arguments := make([]any, len(pids))
	for i, pid := range pids {
		arguments[i] = pid
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(pids)), ",")
	rows, err := s.handle().Query(`SELECT pid, pseudo FROM pseudos WHERE pid IN (`+marks+`)`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			pid    uint32
			pseudo string
		)
		if err := rows.Scan(&pid, &pseudo); err != nil {
			return nil, err
		}
		names[pid] = pseudo
	}
	return names, rows.Err()
}

// Register returns "created" or "exists"; AlreadyRegisteredError when the pid has another key.
func (s *Store) Register(pid uint32, password string) (string, error) {
	if err := CheckPassword(password); err != nil {
		return "", err
	}
	key := DeriveKey(password, pid)
	stored, err := s.Key(pid)
	if err != nil {
		return "", err
	}
	if stored != nil {
		if subtle.ConstantTimeCompare(stored, key) == 1 {
			return "exists", nil
		}
		return "", &AlreadyRegisteredError{"this pid is already registered with another password"}
	}
	if _, err := s.handle().Exec(`INSERT INTO accounts (pid, key, created) VALUES (?, ?, ?)`, pid, key, Now()); err != nil {
		return "", err
	}
	s.restrictPermissions()
	return "created", nil
}

// Verify checks a password against the stored key; storage failures count as a refusal.
func (s *Store) Verify(pid uint32, password string) bool {
	stored, err := s.Key(pid)
	if err != nil || stored == nil {
		return false
	}
	for i := 0; i < len(password); i++ {
		if password[i] >= 0x80 {
			return false
		}
	}
	return subtle.ConstantTimeCompare(stored, DeriveKey(password, pid)) == 1
}

// Allow is false when this address failed too many times inside the window.
func (s *Store) Allow(ip string) (bool, error) {
	var failures int
	err := s.handle().QueryRow(`SELECT COUNT(*) FROM failures WHERE ip = ? AND at >= ?`,
		IPKey(ip), s.Clock()-s.Window).Scan(&failures)
	return failures < s.MaxAttempts, err
}

// Failure counts one failure; registrations also count their successes (bounded creation).
func (s *Store) Failure(ip string) error {
	now := s.Clock()
	transaction, err := s.handle().Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec(`DELETE FROM failures WHERE at < ?`, now-s.Window); err != nil {
		return err
	}
	if _, err := transaction.Exec(`INSERT INTO failures (ip, at) VALUES (?, ?)`, IPKey(ip), now); err != nil {
		return err
	}
	return transaction.Commit()
}

// ForgetFailures clears an address's counter.
func (s *Store) ForgetFailures(ip string) error {
	_, err := s.handle().Exec(`DELETE FROM failures WHERE ip = ?`, IPKey(ip))
	return err
}

// Ban is one operator ban. A pid-only ban blocks the pid anywhere; an ip-only ban blocks the
// address; a pair blocks only that pair.
type Ban struct {
	PID     *uint32
	IP      *string
	Reason  string
	Created float64
	Expires *float64
}

// LogEntry is one operator action.
type LogEntry struct {
	At     float64
	Action string
	PID    *uint32
	IP     *string
	Detail *string
}

func nullablePID(pid *uint32) any {
	if pid == nil {
		return nil
	}
	return *pid
}

func nullableIP(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

func truncate(text string, limit int) string {
	runes := []rune(text)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return text
}

// AddBan bans a pid and/or an address ("" for none), for hours or (nil) for good, and logs it.
// Banning the same target again replaces the ban.
func (s *Store) AddBan(pid *uint32, ip, reason string, hours *float64) error {
	if pid == nil && ip == "" {
		return invalid("a ban needs a pid, an ip, or both")
	}
	if ip != "" {
		if ip = IPKey(ip); ip == "unknown" {
			return invalid("not an IP address")
		}
	}
	now := s.Clock()
	length := "permanent"
	var expires any
	if hours != nil {
		if !(*hours > 0 && *hours <= 24*365) {
			return invalid("hours must be between 0 and one year")
		}
		expires = now + *hours*3600
		length = strconv.FormatFloat(*hours, 'g', 6, 64) + " h"
	}
	reason = truncate(reason, maxReason)
	transaction, err := s.handle().Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := deleteBan(transaction, pid, ip); err != nil {
		return err
	}
	if _, err := transaction.Exec(`INSERT INTO bans (pid, ip, reason, created, expires) VALUES (?, ?, ?, ?, ?)`,
		nullablePID(pid), nullableIP(ip), reason, now, expires); err != nil {
		return err
	}
	if err := s.writeLog(transaction, "ban", pid, ip, length+": "+reason); err != nil {
		return err
	}
	return transaction.Commit()
}

// Unban removes a ban and logs it.
func (s *Store) Unban(pid *uint32, ip string) error {
	if pid == nil && ip == "" {
		return invalid("an unban needs a pid, an ip, or both")
	}
	if ip != "" {
		ip = IPKey(ip)
	}
	transaction, err := s.handle().Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := deleteBan(transaction, pid, ip); err != nil {
		return err
	}
	if err := s.writeLog(transaction, "unban", pid, ip, ""); err != nil {
		return err
	}
	return transaction.Commit()
}

// UNIQUE(pid, ip) does not hold for NULLs, so the same ban is dropped by hand.
func deleteBan(transaction *sql.Tx, pid *uint32, ip string) error {
	var err error
	switch {
	case pid != nil && ip != "":
		_, err = transaction.Exec(`DELETE FROM bans WHERE pid = ? AND ip = ?`, *pid, ip)
	case pid != nil:
		_, err = transaction.Exec(`DELETE FROM bans WHERE pid = ? AND ip IS NULL`, *pid)
	default:
		_, err = transaction.Exec(`DELETE FROM bans WHERE ip = ? AND pid IS NULL`, ip)
	}
	return err
}

func (s *Store) writeLog(transaction *sql.Tx, action string, pid *uint32, ip, detail string) error {
	if _, err := transaction.Exec(`INSERT INTO mod_log (at, action, pid, ip, detail) VALUES (?, ?, ?, ?, ?)`,
		s.Clock(), action, nullablePID(pid), nullableIP(ip), truncate(detail, maxReason)); err != nil {
		return err
	}
	_, err := transaction.Exec(`DELETE FROM mod_log WHERE rowid <= (SELECT MAX(rowid) FROM mod_log) - ?`, maxModLogRows)
	return err
}

// LogAction records what an operator did (a kick, for instance).
func (s *Store) LogAction(action string, pid *uint32, ip, detail string) error {
	transaction, err := s.handle().Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := s.writeLog(transaction, truncate(action, 20), pid, ip, detail); err != nil {
		return err
	}
	return transaction.Commit()
}

// ModLog is the latest operator actions, newest first.
func (s *Store) ModLog(limit int) ([]LogEntry, error) {
	limit = max(1, min(limit, 500))
	rows, err := s.handle().Query(`SELECT at, action, pid, ip, detail FROM mod_log ORDER BY rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []LogEntry{}
	for rows.Next() {
		var entry LogEntry
		if err := rows.Scan(&entry.At, &entry.Action, &entry.PID, &entry.IP, &entry.Detail); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// Bans lists the active bans, newest first.
func (s *Store) Bans() ([]Ban, error) {
	rows, err := s.handle().Query(`SELECT pid, ip, reason, created, expires FROM bans
		WHERE expires IS NULL OR expires > ? ORDER BY created DESC`, s.Clock())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bans := []Ban{}
	for rows.Next() {
		var (
			ban    Ban
			reason sql.NullString
		)
		if err := rows.Scan(&ban.PID, &ban.IP, &reason, &ban.Created, &ban.Expires); err != nil {
			return nil, err
		}
		ban.Reason = reason.String
		bans = append(bans, ban)
	}
	return bans, rows.Err()
}

// IsBanned checks a pid (nil for none) and a source address ("" for none). A storage failure
// counts as not banned and is returned for the caller to log.
func (s *Store) IsBanned(pid *uint32, ip string) (bool, error) {
	var key any
	if ip != "" {
		key = IPKey(ip)
	}
	var found int
	err := s.handle().QueryRow(`SELECT 1 FROM bans WHERE ((pid = ? AND ip IS NULL)
		OR (ip = ? AND pid IS NULL) OR (pid = ? AND ip = ?))
		AND (expires IS NULL OR expires > ?) LIMIT 1`,
		nullablePID(pid), key, nullablePID(pid), key, s.Clock()).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
