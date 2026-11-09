// Package social is friends by pseudo: unique pseudos, who is online, and presence for MUTUAL
// friends. The server keeps a pseudo per account and, in memory only, who sent a heartbeat lately
// with their game mode and the pids they added. A friend's presence is returned only when both
// players listed each other: the friend lists themselves live on the players' PCs.
package social

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/jsonval"
	"github.com/lgicbd/SplatPc-Server/internal/limit"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
)

const (
	OnlineWindow = 30.0 // seconds without a heartbeat before a player counts as offline
	TokenTTL     = 12 * 3600.0
	MaxFriends   = 100 // what the game's friend list holds
	MaxTokens    = 20000
)

var (
	pseudoRE  = regexp.MustCompile(`^[A-Za-z0-9 _.\-]{2,10}$`)
	modeRE    = regexp.MustCompile(`^[0-9a-f]{88}$`) // the game's 0x2C-byte GameMode, hex
	hashRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE = regexp.MustCompile(`^\d{1,4}\.\d{1,4}(\.\d{1,4})?$`)

	// Names nobody may take: they would pass for the project, the server or its staff.
	reserved = map[string]bool{"admin": true, "administrator": true, "moderator": true, "mod": true, "staff": true,
		"support": true, "server": true, "system": true, "nintendo": true, "splatoon": true, "official": true,
		"owner": true, "root": true, "console": true, "player": true}
)

// Error is a request the server refuses: an HTTP status and a short message.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// CleanPseudo returns the pseudo as stored, or false when the launcher would not accept it.
func CleanPseudo(value any) (string, bool) {
	text, isText := value.(string)
	if !isText {
		return "", false
	}
	text = strings.TrimSpace(text)
	return text, pseudoRE.MatchString(text)
}

// Friend is one mutual friend online.
type Friend struct {
	PID  string `json:"pid"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type session struct {
	pid     uint32
	expires float64
}

type presence struct {
	seen    float64
	mode    string
	friends map[uint32]bool
}

type attestation struct {
	at      float64
	version string
}

// Social holds sessions and presence for the HTTP endpoints.
type Social struct {
	Accounts      *accounts.Store
	Clock         func() float64
	IntegrityMode string // off | log | enforce
	releases      map[string]map[string]bool

	mu        sync.Mutex
	attested  map[uint32]attestation
	tokens    map[string]session
	tokenOf   map[uint32]string
	presences map[uint32]presence
	nextPrune float64

	SessionRate  *limit.Limiter // sign-ins and pseudo claims, per source address
	AuthRate     *limit.Limiter // the same for the whole server: each check costs CPU
	LookupRate   *limit.Limiter // searches, per player
	LookupIPRate *limit.Limiter // searches, per source address
	PresenceRate *limit.Limiter // per player (a heartbeat every 5 s is 12 per minute)
	RequestRate  *limit.Limiter // friend requests sent, per player
	AnswerRate   *limit.Limiter // answers and cancellations, per player

	requestMu sync.Mutex // one friend request change at a time: they read then write
}

// New takes the release table version -> code hashes; a nil clock is the wall clock.
func New(store *accounts.Store, clock func() float64, integrityMode string, releases map[string][]string) *Social {
	if clock == nil {
		clock = accounts.Now
	}
	if integrityMode == "" {
		integrityMode = "off"
	}
	table := map[string]map[string]bool{}
	for version, hashes := range releases {
		table[version] = map[string]bool{}
		for _, hash := range hashes {
			table[version][hash] = true
		}
	}
	return &Social{Accounts: store, Clock: clock, IntegrityMode: integrityMode, releases: table,
		attested: map[uint32]attestation{}, tokens: map[string]session{}, tokenOf: map[uint32]string{},
		presences:   map[uint32]presence{},
		SessionRate: limit.New(30, 60, nil), AuthRate: limit.New(300, 60, nil),
		LookupRate: limit.New(20, 60, nil), LookupIPRate: limit.New(60, 60, nil), PresenceRate: limit.New(40, 60, nil),
		RequestRate: limit.New(10, 60, nil), AnswerRate: limit.New(30, 60, nil)}
}

// AllowAuth is false when this address, or the server as a whole, had too many password checks.
func (s *Social) AllowAuth(ip string) bool {
	return s.SessionRate.Allow(accounts.IPKey(ip)) && s.AuthRate.Allow("all")
}

func (s *Social) refuseBanned(pid uint32) error {
	banned, err := s.Accounts.IsBanned(&pid, "")
	if err != nil {
		logx.Errorf("ban check failed: %v", err)
		return &Error{500, "internal error"}
	}
	if banned {
		return &Error{403, "this player is banned"}
	}
	return nil
}

// PIDOf resolves a session token; 0 when unknown or expired.
func (s *Social) PIDOf(token string) uint32 {
	now := s.Clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, known := s.tokens[token]
	if !known {
		return 0
	}
	if entry.expires < now {
		s.forgetToken(token)
		return 0
	}
	return entry.pid
}

// CheckClient says whether the client's code hash belongs to a listed release: the release's
// version on success, the reason to show on failure.
func (s *Social) CheckClient(client any) (bool, string) {
	const noProof = "no integrity proof (update the game)"
	proof, isObject := client.(map[string]any)
	if !isObject {
		return false, noProof
	}
	code, isText := proof["code"].(string)
	if !isText || !hashRE.MatchString(code) {
		return false, noProof
	}
	versions := make([]string, 0, len(s.releases))
	for version := range s.releases {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	for _, version := range versions {
		if s.releases[version][code] {
			return true, version
		}
	}
	claimed := "?"
	if text, isText := proof["version"].(string); isText && versionRE.MatchString(text) {
		claimed = text
	}
	need := ""
	if latest := s.LatestVersion(); latest != "" {
		need = " to " + latest
	}
	return false, fmt.Sprintf("game files not recognised (version %s): update the game%s, or restore the official files", claimed, need)
}

// LatestVersion is the highest listed release, "" when none; published in /health so launchers
// can warn.
func (s *Social) LatestVersion() string {
	latest := ""
	var latestParts []int
	for version := range s.releases {
		parts, valid := versionParts(version)
		if !valid {
			return ""
		}
		if latest == "" || compareVersions(parts, latestParts) > 0 {
			latest, latestParts = version, parts
		}
	}
	return latest
}

func versionParts(version string) ([]int, bool) {
	fields := strings.Split(version, ".")
	parts := make([]int, len(fields))
	for i, field := range fields {
		number, err := strconv.Atoi(field)
		if err != nil {
			return nil, false
		}
		parts[i] = number
	}
	return parts, true
}

func compareVersions(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return len(a) - len(b)
}

// IsAttested is false only when integrity is enforced and this player has not proved a listed
// release lately.
func (s *Social) IsAttested(pid uint32) bool {
	if s.IntegrityMode != "enforce" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, known := s.attested[pid]
	return known && s.Clock()-entry.at <= TokenTTL
}

// OpenSession returns a token for a player whose password is right (checked once; the token does
// the rest). One session per player: tokens cannot pile up.
func (s *Social) OpenSession(pid uint32, password string, client any) (string, error) {
	if !s.Accounts.Verify(pid, password) {
		return "", &Error{401, "unknown player or wrong password"}
	}
	if err := s.refuseBanned(pid); err != nil {
		return "", err
	}
	if s.IntegrityMode != "off" {
		valid, detail := s.CheckClient(client)
		switch {
		case valid:
			s.mu.Lock()
			s.attested[pid] = attestation{s.Clock(), detail}
			s.mu.Unlock()
		default:
			logx.Warnf("integrity: pid %08x refused proof (%s) mode=%s", pid, detail, s.IntegrityMode)
			if s.IntegrityMode == "enforce" {
				s.mu.Lock()
				delete(s.attested, pid)
				s.mu.Unlock()
				return "", &Error{426, detail}
			}
		}
	}
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := hex.EncodeToString(secret)
	now := s.Clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tokens) >= MaxTokens {
		s.prune(now, true)
	}
	if previous, known := s.tokenOf[pid]; known {
		delete(s.tokens, previous)
	}
	s.tokens[token] = session{pid, now + TokenTTL}
	s.tokenOf[pid] = token
	return token, nil
}

const pseudoRules = "2 to 10 characters: letters, digits, space, _ - ."

// ClaimPseudo gives the pseudo to a player whose password is right.
func (s *Social) ClaimPseudo(pid uint32, password string, pseudo any) (string, error) {
	if !s.Accounts.Verify(pid, password) {
		return "", &Error{401, "unknown player or wrong password"}
	}
	if err := s.refuseBanned(pid); err != nil {
		return "", err
	}
	clean, valid := CleanPseudo(pseudo)
	if !valid {
		return "", &Error{400, pseudoRules}
	}
	if reserved[strings.ToLower(clean)] {
		return "", &Error{400, "this pseudo is reserved"}
	}
	won, err := s.Accounts.ClaimPseudo(pid, clean)
	if err != nil {
		logx.Errorf("pseudo claim failed: %v", err)
		return "", &Error{500, "internal error"}
	}
	if !won {
		return "", &Error{409, "this pseudo is taken"}
	}
	return clean, nil
}

// Lookup finds a player by pseudo.
func (s *Social) Lookup(token string, pseudo any, ip string) (map[string]any, error) {
	pid := s.PIDOf(token)
	if pid == 0 {
		return nil, &Error{401, "session expired"}
	}
	if err := s.refuseBanned(pid); err != nil {
		return nil, err
	}
	if !s.LookupRate.Allow(strconv.FormatUint(uint64(pid), 10)) || !s.LookupIPRate.Allow(accounts.IPKey(ip)) {
		return nil, &Error{429, "too many searches, wait a moment"}
	}
	clean, valid := CleanPseudo(pseudo)
	if !valid {
		return nil, &Error{400, pseudoRules}
	}
	found, err := s.Accounts.PIDForPseudo(clean)
	if err == nil && found == 0 {
		return map[string]any{"found": false}, nil
	}
	var name string
	if err == nil {
		name, err = s.Accounts.PseudoOf(found)
	}
	if err != nil {
		logx.Errorf("pseudo lookup failed: %v", err)
		return nil, &Error{500, "internal error"}
	}
	return map[string]any{"found": true, "pid": fmt.Sprintf("%08x", found), "pseudo": name,
		"online": s.online(found), "self": found == pid}, nil
}

func (s *Social) online(pid uint32) bool {
	now := s.Clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, known := s.presences[pid]
	return known && now-entry.seen <= OnlineWindow
}

// parseFriend reads a pid from a friend list: plain hex, junk is ignored.
func parseFriend(value any) (uint32, bool) {
	text := strings.ToLower(strings.TrimSpace(jsonval.Str(value)))
	text = strings.TrimPrefix(strings.TrimPrefix(text, "+"), "0x")
	number, err := strconv.ParseUint(text, 16, 64)
	if err != nil || number == 0 || number > accounts.MaxPID {
		return 0, false
	}
	return uint32(number), true
}

// Heartbeat records this player's presence and returns the MUTUAL friends who are online.
func (s *Social) Heartbeat(token string, mode, friends any) ([]Friend, error) {
	pid := s.PIDOf(token)
	if pid == 0 {
		return nil, &Error{401, "session expired"}
	}
	if err := s.refuseBanned(pid); err != nil {
		return nil, err
	}
	if !s.PresenceRate.Allow(strconv.FormatUint(uint64(pid), 10)) {
		return nil, &Error{429, "too many updates"}
	}
	modeText := ""
	if jsonval.Truthy(mode) {
		modeText = jsonval.Str(mode)
	}
	if modeText != "" && !modeRE.MatchString(modeText) {
		return nil, &Error{400, "invalid game mode"}
	}
	listed, _ := friends.([]any)
	if len(listed) > MaxFriends {
		listed = listed[:MaxFriends]
	}
	wanted := map[uint32]bool{}
	var ordered []uint32
	for _, value := range listed {
		if friend, valid := parseFriend(value); valid && friend != pid && !wanted[friend] {
			wanted[friend] = true
			ordered = append(ordered, friend)
		}
	}

	now := s.Clock()
	visible := []uint32{}
	modes := map[uint32]string{}
	s.mu.Lock()
	s.presences[pid] = presence{now, modeText, wanted}
	if entry, known := s.attested[pid]; known { // still playing: the proof does not run out mid-session
		s.attested[pid] = attestation{now, entry.version}
	}
	s.prune(now, false)
	for _, friend := range ordered {
		entry, known := s.presences[friend]
		if known && now-entry.seen <= OnlineWindow && entry.friends[pid] {
			visible = append(visible, friend)
			modes[friend] = entry.mode
		}
	}
	s.mu.Unlock()

	names, err := s.Accounts.PseudosFor(visible)
	if err != nil {
		logx.Errorf("pseudo read failed: %v", err)
		return nil, &Error{500, "internal error"}
	}
	result := make([]Friend, 0, len(visible))
	for _, friend := range visible {
		name, named := names[friend]
		if !named {
			name = "Ami"
		}
		result = append(result, Friend{fmt.Sprintf("%08x", friend), name, modes[friend]})
	}
	return result, nil
}

func (s *Social) prune(now float64, force bool) {
	if !force && now < s.nextPrune {
		return
	}
	s.nextPrune = now + 30
	for pid, entry := range s.presences {
		if now-entry.seen > OnlineWindow*4 {
			delete(s.presences, pid)
		}
	}
	for token, entry := range s.tokens {
		if entry.expires < now {
			s.forgetToken(token)
		}
	}
	for pid, entry := range s.attested {
		if now-entry.at > TokenTTL {
			delete(s.attested, pid)
		}
	}
	for token := range s.tokens {
		if len(s.tokens) < MaxTokens {
			break
		}
		s.forgetToken(token)
	}
}

func (s *Social) forgetToken(token string) {
	entry, known := s.tokens[token]
	if !known {
		return
	}
	delete(s.tokens, token)
	if s.tokenOf[entry.pid] == token {
		delete(s.tokenOf, entry.pid)
	}
}

// Revoke drops a player's session, presence and integrity proof: a ban takes effect at once.
func (s *Social) Revoke(pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token, known := s.tokenOf[pid]; known {
		s.forgetToken(token)
	}
	delete(s.presences, pid)
	delete(s.attested, pid)
}

// OnlineCount is the number of players with a recent heartbeat.
func (s *Social) OnlineCount() int {
	now := s.Clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, entry := range s.presences {
		if now-entry.seen <= OnlineWindow {
			count++
		}
	}
	return count
}
