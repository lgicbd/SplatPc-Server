package nex

import (
	"fmt"
	"strconv"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/kerberos"
	"github.com/lgicbd/SplatPc-Server/internal/limit"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/matchmake"
	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
)

const (
	protocolAuth = 10
	serverName   = "branch:origin/project/wup-agmj build:3_8_15_2004_0"
	securePID    = 2

	maxLoginsPerIP   = 60
	maxTicketsPerPID = 20
	rateWindow       = 60.0
	maxUsernameSize  = 10
)

// auth is the authentication protocol: it hands out tickets for the secure server.
type auth struct {
	public     bool
	secureKey  []byte
	station    string
	lanStation string // for players on the server's own LAN; "" when there is none
	accounts   *accounts.Store
	attested   func(uint32) bool // nil: no integrity check
	identities []string
	roots      []string
	ipRate     *limit.Limiter
	pidRate    *limit.Limiter
}

func (a *auth) methods() rmc.Methods {
	return rmc.Methods{1: a.login, 2: a.loginEx, 3: a.requestTicket}
}

func parseUsername(username string) (uint32, error) {
	if username == "" || len(username) > maxUsernameSize {
		return 0, rmc.Refuse(rmc.InvalidUsername)
	}
	for _, c := range []byte(username) {
		if c < '0' || c > '9' {
			return 0, rmc.Refuse(rmc.InvalidUsername)
		}
	}
	pid, err := strconv.ParseUint(username, 10, 64)
	if err != nil || pid == 0 || pid > maxIdentityPID {
		return 0, rmc.Refuse(rmc.InvalidUsername)
	}
	return uint32(pid), nil
}

func (a *auth) userKey(pid uint32, origin string) ([]byte, error) {
	refused := rmc.Refuse(rmc.InvalidUsername) // every refusal looks the same to the caller
	if !a.ipRate.Allow(origin) {
		logx.Warnf("login from %s refused: too many login attempts per minute", origin)
		return nil, refused
	}
	if !a.pidRate.Allow(fmt.Sprintf("%d/%s", pid, origin)) { // both: a stranger cannot lock a pid out
		logx.Warnf("login for pid %08x refused: too many tickets per minute", pid)
		return nil, refused
	}
	if !a.public {
		password, found := findPassword(pid, a.identities, a.roots)
		if !found {
			logx.Warnf("no identity for pid %08x", pid)
			return nil, refused
		}
		return accounts.DeriveKey(password, pid), nil
	}
	if a.accounts == nil {
		return nil, refused
	}
	banned, err := a.accounts.IsBanned(&pid, origin)
	if err != nil {
		return nil, err
	}
	if banned {
		logx.Warnf("banned login refused: pid %08x from %s", pid, origin)
		return nil, refused
	}
	if a.attested != nil && !a.attested(pid) {
		logx.Warnf("login refused: pid %08x has not proved an official game version (integrity enforce)", pid)
		return nil, refused
	}
	key, err := a.accounts.Key(pid)
	if err != nil {
		return nil, err
	}
	if key != nil {
		return key, nil
	}
	// Only unknown pids count against an address: behind a shared one, other players' sign-ups must
	// not lock out the accounts that already exist.
	allowed, err := a.accounts.Allow(origin)
	if err != nil {
		return nil, err
	}
	if !allowed {
		logx.Warnf("login from %s: too many unknown pids, refused for now", origin)
		return nil, refused
	}
	if err := a.accounts.Failure(origin); err != nil {
		return nil, err
	}
	logx.Warnf("unknown pid %08x from %s: register the account first", pid, origin)
	return nil, refused
}

func (a *auth) ticket(pid uint32, userKey []byte) ([]byte, error) {
	sessionKey := kerberos.RandomBytes(kerberos.SessionKeySize)
	internal, err := kerberos.ServerTicket{Timestamp: time.Now(), Source: pid, SessionKey: sessionKey}.Encrypt(a.secureKey)
	if err != nil {
		return nil, err
	}
	return kerberos.ClientTicket{SessionKey: sessionKey, Target: securePID, Internal: internal}.Encrypt(userKey)
}

func (a *auth) answer(c *rmc.Conn, username string, out *nexstream.Writer) error {
	pid, err := parseUsername(username)
	if err != nil {
		return err
	}
	origin := c.RemoteAddr().Addr().String()
	key, err := a.userKey(pid, origin)
	if err != nil {
		return err
	}
	ticket, err := a.ticket(pid, key)
	if err != nil {
		return err
	}
	station := a.station
	if a.lanStation != "" && matchmake.IsPrivate(origin) {
		station = a.lanStation
	}
	out.U32(rmc.Success)
	out.PID(pid)
	out.Buffer(ticket)
	out.Struct(1, func(sub *nexstream.Writer) {
		sub.Text(station)
		sub.U32(0) // no special protocols
		sub.Text("prudp:/")
		if sub.StructHeader {
			sub.U64(nexstream.DateTime(time.Now()))
		}
	})
	out.Text(serverName)
	logx.Infof("ticket issued for pid %08x -> %s", pid, station)
	return nil
}

func (a *auth) login(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	username := in.Text()
	if err := in.Err(); err != nil {
		return err
	}
	return a.answer(c, username, out)
}

func (a *auth) loginEx(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	username := in.Text()
	in.AnyData() // the game's token: nothing depends on it
	if err := in.Err(); err != nil {
		return err
	}
	return a.answer(c, username, out)
}

func (a *auth) requestTicket(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	source := in.PID()
	target := in.PID()
	if err := in.Err(); err != nil {
		return err
	}
	if target != securePID {
		return rmc.Refuse(rmc.InvalidUsername)
	}
	key, err := a.userKey(source, c.RemoteAddr().Addr().String())
	if err != nil {
		return err
	}
	ticket, err := a.ticket(source, key)
	if err != nil {
		return err
	}
	out.U32(rmc.Success)
	out.Buffer(ticket)
	return nil
}
