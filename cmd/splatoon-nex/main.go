// Command splatoon-nex is the Splatoon NEX server. `accounts` and `ops` are its operator tools.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/config"
	"github.com/lgicbd/SplatPc-Server/internal/httpapi"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/matchmake"
	"github.com/lgicbd/SplatPc-Server/internal/natcheck"
	"github.com/lgicbd/SplatPc-Server/internal/nex"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
	"github.com/lgicbd/SplatPc-Server/internal/social"
)

const defaultIdleTimeout = 60 * time.Second

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "accounts":
			os.Exit(accounts.RunCLI(args[1:], os.Stdin, os.Stdout, os.Stderr))
		case "ops":
			os.Exit(runOps(args[1:], os.Stdout, os.Stderr))
		}
	}
	os.Exit(runServer(args, os.Stderr))
}

type serverFlags struct {
	config.Flags
	log     string
	debug   bool
	seconds float64
}

func parseServerFlags(args []string, stderr io.Writer) (*serverFlags, error) {
	var parsed serverFlags
	fs := flag.NewFlagSet("splatoon-nex", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repeated := func(target *[]string) func(string) error {
		return func(value string) error {
			*target = append(*target, value)
			return nil
		}
	}
	fs.StringVar(&parsed.ConfigFile, "config", "", "server configuration file (JSON)")
	fs.StringVar(&parsed.Mode, "mode", "", "lab or public")
	fs.BoolVar(&parsed.Public, "public", false, "same as --mode public")
	fs.StringVar(&parsed.Listen, "listen", "", "address to bind")
	fs.StringVar(&parsed.Advertise, "advertise", "", "address given to players for the secure server")
	port := fs.Int("port", 0, "auth port")
	securePort := fs.Int("secure-port", 0, "secure port (default: auth port + 1)")
	natcheckOn := fs.Bool("natcheck", false, "answer NAT checks")
	natcheckOff := fs.Bool("no-natcheck", false, "do not answer NAT checks")
	fs.Func("natcheck-address", "address the NAT check binds (repeatable)", repeated(&parsed.NatcheckAddresses))
	fs.Func("identity", "identity file, lab mode (repeatable)", repeated(&parsed.Identities))
	fs.Func("identity-root", "folder of identity files, lab mode (repeatable)", repeated(&parsed.IdentityRoots))
	fs.StringVar(&parsed.AccountsDB, "accounts-db", "", "account database, public mode")
	fs.StringVar(&parsed.Registration, "registration", "", "open, token or closed")
	fs.StringVar(&parsed.RegistrationToken, "registration-token", "", "registration token")
	registrationPort := fs.Int("registration-port", 0, "HTTP endpoint port")
	fill := fs.Float64("fill-timeout", 0, "seconds a public session waits for players")
	fs.StringVar(&parsed.log, "log", "nexserver.log", "log file")
	fs.Float64Var(&parsed.seconds, "seconds", 0, "stop after this long (tests)")
	fs.BoolVar(&parsed.debug, "debug", false, "verbose log")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	fs.Visit(func(given *flag.Flag) {
		switch given.Name {
		case "port":
			parsed.Port = port
		case "secure-port":
			parsed.SecurePort = securePort
		case "registration-port":
			parsed.RegistrationPort = registrationPort
		case "fill-timeout":
			parsed.FillTimeout = fill
		case "natcheck":
			parsed.Natcheck = natcheckOn
		case "no-natcheck":
			off := !*natcheckOff
			parsed.Natcheck = &off
		}
	})
	return &parsed, nil
}

// live gives the HTTP endpoint its view of the game server.
type live struct{ matchmaker *matchmake.Matchmaker }

func (l live) Stats() httpapi.Stats {
	players, sessions, connections := l.matchmaker.Stats()
	return httpapi.Stats{Players: players, Sessions: sessions, Connections: connections}
}
func (l live) Errors() uint64          { return rmc.Failures() }
func (l live) ActivePlayers() []uint32 { return l.matchmaker.ActivePlayers() }
func (l live) RequestKick(pid uint32)  { l.matchmaker.Kick(pid) }
func (l live) Sessions() []httpapi.SessionInfo {
	sessions := l.matchmaker.Sessions()
	list := make([]httpapi.SessionInfo, len(sessions))
	for i, session := range sessions {
		list[i] = httpapi.SessionInfo{ID: session.ID, Host: session.Host, Members: session.Members, Closed: session.Closed}
	}
	return list
}

func idleTimeout() time.Duration {
	if seconds, err := strconv.ParseFloat(os.Getenv("NEXLAB_IDLE_TIMEOUT"), 64); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	return defaultIdleTimeout
}

func wildcard(host string) bool { return host == "" || host == "0.0.0.0" || host == "::" }

func runServer(args []string, stderr io.Writer) int {
	flags, err := parseServerFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	cfg, err := config.Resolve(flags.Flags)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := logx.Setup(flags.log, flags.debug); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := serve(cfg, flags.seconds); err != nil {
		logx.Errorf("%v", err)
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func serve(cfg *config.Config, seconds float64) error {
	var (
		store    *accounts.Store
		endpoint *httpapi.Server
		err      error
		attested func(uint32) bool
		nat      *natcheck.Server
	)
	if cfg.Natcheck {
		addresses := cfg.NatcheckAddresses
		if addresses == nil {
			addresses = natcheck.LabAddresses
		}
		nat = natcheck.Start(addresses, natcheck.Ports, cfg.NatcheckSameSocket)
		defer nat.Close()
	}
	options := matchmake.Options{Public: cfg.IsPublic(), FillTimeout: cfg.FillTimeout,
		RandomSessionKey: cfg.RandomSessionKey, LANPublic: os.Getenv("NEXLAB_LAN_PUBLIC")}
	if nat != nil {
		options.NAT = nat
	}
	matchmaker := matchmake.New(options)
	defer matchmaker.Stop()

	if cfg.IsPublic() {
		if store, err = accounts.Open(cfg.AccountsDB); err != nil {
			return fmt.Errorf("accounts database: %w", err)
		}
		defer store.Close()
		count, _ := store.Count()
		logx.Infof("accounts: %d in %s (registration %s, port %d)", count, cfg.AccountsDB, cfg.Registration, cfg.RegistrationPort)
		if cfg.Registration != "closed" {
			friends := social.New(store, nil, cfg.IntegrityMode, cfg.IntegrityReleases)
			attested = friends.IsAttested
			httpOptions := httpapi.Options{Accounts: store, Social: friends, Live: live{matchmaker},
				AdminToken: cfg.AdminToken, BehindProxy: cfg.RegistrationProxy, MinClientVersion: cfg.MinClientVersion}
			if cfg.Registration == "token" {
				httpOptions.Token = cfg.RegistrationToken
			}
			endpoint = httpapi.New(httpOptions)
			host := cfg.Listen
			if cfg.RegistrationProxy {
				host = "127.0.0.1"
			} else if wildcard(host) {
				host = "0.0.0.0"
			}
			if err := endpoint.Start(host, cfg.RegistrationPort); err != nil {
				return fmt.Errorf("registration endpoint: %w", err)
			}
			defer endpoint.Stop()
		}
	}

	server, err := nex.Start(nex.Options{Config: cfg, Accounts: store, Attested: attested, Matchmaker: matchmaker,
		AdvertiseLAN: os.Getenv("NEXLAB_ADVERTISE_LAN"), IdleTimeout: idleTimeout()})
	if err != nil {
		return err
	}
	defer server.Close()
	logx.Infof("%s", cfg.Describe())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if seconds > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, time.Duration(seconds*float64(time.Second)))
		defer cancelTimeout()
	}
	<-ctx.Done()
	logx.Infof("server stopped")
	return nil
}
