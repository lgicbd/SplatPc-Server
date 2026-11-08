// Package config holds the settings of the NEX server. Defaults reproduce the lab server: bound
// to 127.0.0.1, auth on 60000, secure on 60001, NAT check on the loopback aliases, identities read
// from online_identity.ini. A JSON file or command-line switches select public mode, where a player
// is where its packets come from. Every key is optional; `_`-prefixed keys are notes and are
// ignored. See deploy/server.example.json.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/lgicbd/SplatPc-Server/internal/jsonval"
)

const (
	ModeLab    = "lab"
	ModePublic = "public"

	RegistrationOpen   = "open"
	RegistrationToken  = "token"
	RegistrationClosed = "closed"

	IntegrityOff     = "off"
	IntegrityLog     = "log"
	IntegrityEnforce = "enforce"
)

var (
	versionRE = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)
	hashRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fields    = []string{"mode", "listen", "advertise", "auth_port", "secure_port", "natcheck",
		"natcheck_addresses", "identities", "identity_roots",
		"accounts_db", "registration", "registration_port", "registration_token",
		"fill_timeout", "natcheck_single_ip", "natcheck_same_socket", "registration_proxy",
		"min_client_version", "random_session_key", "admin_token",
		"integrity_mode", "integrity_releases"}
)

// Error is a configuration value that is missing, out of range, or inconsistent.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func errorf(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// Config is a validated server configuration.
type Config struct {
	Mode               string
	Listen             string
	Advertise          string
	AuthPort           int
	SecurePort         int
	Natcheck           bool
	NatcheckAddresses  []string // nil: the lab's loopback pair
	NatcheckSingleIP   bool
	NatcheckSameSocket bool
	RegistrationProxy  bool
	RandomSessionKey   bool
	MinClientVersion   string
	Identities         []string
	IdentityRoots      []string // nil: the default roots
	HasIdentityRoots   bool
	AccountsDB         string
	Registration       string
	RegistrationPort   int
	RegistrationToken  string
	AdminToken         string
	IntegrityMode      string
	IntegrityReleases  map[string][]string
	FillTimeout        float64

	provided map[string]bool
}

// New validates raw settings (as read from JSON). A nil map gives the defaults.
func New(values map[string]any) (*Config, error) {
	var unknown []string
	provided := map[string]bool{}
	known := map[string]bool{}
	for _, field := range fields {
		known[field] = true
	}
	for key := range values {
		switch {
		case known[key]:
			provided[key] = true
		case !strings.HasPrefix(key, "_"):
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, errorf("unknown setting(s): %s", strings.Join(unknown, ", "))
	}

	c := &Config{provided: provided}
	c.Mode = "lab"
	if value, ok := values["mode"]; ok {
		c.Mode = strings.ToLower(strings.TrimSpace(jsonval.Str(value)))
	}
	listen, hasListen := values["listen"]
	if !hasListen {
		listen = defaultListen(c.Mode)
	}
	c.NatcheckSingleIP = jsonval.Truthy(values["natcheck_single_ip"])
	c.NatcheckSameSocket = jsonval.Truthy(values["natcheck_same_socket"])
	c.RegistrationProxy = jsonval.Truthy(values["registration_proxy"])
	c.RandomSessionKey = jsonval.Truthy(values["random_session_key"])

	if err := c.setMinClientVersion(values["min_client_version"]); err != nil {
		return nil, err
	}
	if !jsonval.Truthy(values["identities"]) {
		c.Identities = []string{}
	} else {
		c.Identities = strings1(values["identities"])
	}
	if roots, ok := values["identity_roots"]; ok && roots != nil {
		c.IdentityRoots = strings1(roots)
		c.HasIdentityRoots = true
	}
	if jsonval.Truthy(values["admin_token"]) {
		c.AdminToken = jsonval.Str(values["admin_token"])
	}
	if err := c.setIntegrity(values); err != nil {
		return nil, err
	}

	// Mode-dependent defaults.
	if value, ok := values["natcheck"]; ok && value != nil {
		c.Natcheck = jsonval.Truthy(value)
	} else {
		c.Natcheck = c.Mode == ModeLab
	}
	if value, ok := values["advertise"]; ok && value != nil {
		c.Advertise = strings.TrimSpace(jsonval.Str(value))
	}
	c.Registration = RegistrationClosed // a public server opens registration deliberately
	if value, ok := values["registration"]; ok && value != nil {
		c.Registration = jsonval.Str(value)
	}
	c.AccountsDB = "nexlab-accounts.sqlite3"
	if value, ok := values["accounts_db"]; ok && value != nil {
		c.AccountsDB = jsonval.Str(value)
	}
	if value, ok := values["registration_token"]; ok && value != nil {
		c.RegistrationToken = jsonval.Str(value)
	}
	c.FillTimeout = 20
	if value, ok := values["fill_timeout"]; ok {
		number, valid := jsonval.Float(value)
		if !valid {
			return nil, errorf("fill_timeout: '%s' is not a number of seconds", jsonval.Str(value))
		}
		c.FillTimeout = number
	}
	if err := c.validate(listen, values); err != nil {
		return nil, err
	}
	return c, nil
}

func defaultListen(mode string) string {
	if strings.ToLower(strings.TrimSpace(mode)) == ModePublic {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

func (c *Config) setMinClientVersion(value any) error {
	if !jsonval.Truthy(value) {
		return nil
	}
	text, isText := value.(string)
	if !isText || !versionRE.MatchString(strings.TrimSpace(text)) {
		return errorf("min_client_version: '%s' is not a version like 0.2.0", jsonval.Str(value))
	}
	c.MinClientVersion = text
	return nil
}

func (c *Config) setIntegrity(values map[string]any) error {
	c.IntegrityMode = IntegrityOff
	if jsonval.Truthy(values["integrity_mode"]) {
		c.IntegrityMode = strings.ToLower(strings.TrimSpace(jsonval.Str(values["integrity_mode"])))
	}
	switch c.IntegrityMode {
	case IntegrityOff, IntegrityLog, IntegrityEnforce:
	default:
		return errorf("integrity_mode: '%s' is not one of off, log, enforce", c.IntegrityMode)
	}
	c.IntegrityReleases = map[string][]string{}
	raw := values["integrity_releases"]
	if jsonval.Truthy(raw) {
		releases, isMap := raw.(map[string]any)
		if !isMap {
			return errorf(`integrity_releases: expected {"0.1.3": "<hash>"}`)
		}
		for version, hashes := range releases {
			name := strings.TrimSpace(version)
			if !versionRE.MatchString(name) {
				return errorf("integrity_releases: '%s' is not a version like 0.2.0", version)
			}
			listed, valid := hashList(hashes)
			if !valid {
				return errorf("integrity_releases: the hash of %s must be 64 lowercase hex digits", version)
			}
			c.IntegrityReleases[name] = listed
		}
	}
	if c.IntegrityMode == IntegrityEnforce && len(c.IntegrityReleases) == 0 {
		return errorf("integrity_mode enforce needs at least one entry in integrity_releases")
	}
	return nil
}

func hashList(value any) ([]string, bool) {
	var listed []string
	switch v := value.(type) {
	case string:
		listed = []string{v}
	case []string:
		listed = v
	case []any:
		for _, item := range v {
			text, isText := item.(string)
			if !isText {
				return nil, false
			}
			listed = append(listed, text)
		}
	default:
		return nil, false
	}
	if len(listed) == 0 {
		return nil, false
	}
	for _, hash := range listed {
		if !hashRE.MatchString(hash) {
			return nil, false
		}
	}
	return listed, true
}

func (c *Config) validate(listen any, values map[string]any) error {
	if c.Mode != ModeLab && c.Mode != ModePublic {
		return errorf("mode: '%s' is not one of lab, public", c.Mode)
	}
	c.Listen = jsonval.Str(listen)
	if !isWildcard(c.Listen) {
		address, err := canonicalIP(c.Listen, "listen")
		if err != nil {
			return err
		}
		c.Listen = address
	}
	if c.Advertise != "" {
		host, err := canonicalHost(c.Advertise, "advertise")
		if err != nil {
			return err
		}
		c.Advertise = host
	} else if isWildcard(c.Listen) {
		return errorf("advertise: required when listen is 0.0.0.0 (players must be told which address to connect back to)")
	}

	var err error
	authValue, ok := values["auth_port"]
	if !ok {
		authValue = 60000
	}
	if c.AuthPort, err = port(authValue, "auth_port"); err != nil {
		return err
	}
	secureValue := values["secure_port"]
	if secureValue == nil {
		secureValue = c.AuthPort + 1
	}
	if c.SecurePort, err = port(secureValue, "secure_port"); err != nil {
		return err
	}
	if c.AuthPort == c.SecurePort {
		return errorf("secure_port must differ from auth_port")
	}
	if !(c.FillTimeout > 0) {
		return errorf("fill_timeout: must be a positive number of seconds")
	}
	if err := c.validateNatcheck(values["natcheck_addresses"]); err != nil {
		return err
	}
	if c.Mode == ModePublic {
		// Players would be told to connect to their own PC.
		for _, item := range [][2]string{{"listen", c.Listen}, {"advertise", c.Advertise}} {
			if isLoopback(item[1]) {
				return errorf("%s: a public server cannot use the loopback address '%s' (players could not reach it)", item[0], item[1])
			}
		}
		for _, address := range c.NatcheckAddresses {
			if isLoopback(address) {
				return errorf("natcheck_addresses: public mode cannot use the loopback address '%s' (the NAT check must be reachable)", address)
			}
		}
	}
	switch c.Registration {
	case RegistrationOpen, RegistrationToken, RegistrationClosed:
	default:
		return errorf("registration: '%s' is not one of open, token, closed", c.Registration)
	}
	if c.Registration == RegistrationToken && c.RegistrationToken == "" {
		return errorf("registration_token: required when registration is 'token'")
	}
	if c.Registration == RegistrationClosed {
		c.RegistrationPort = 0
		return nil
	}
	if !jsonval.Truthy(values["registration_port"]) { // absent, or the 0 left by a closed config
		c.RegistrationPort = c.AuthPort + 2
	} else if c.RegistrationPort, err = port(values["registration_port"], "registration_port"); err != nil {
		return err
	}
	if c.RegistrationPort < 1 || c.RegistrationPort > 65535 {
		return errorf("registration_port: %d is outside 1..65535", c.RegistrationPort)
	}
	return nil
}

func (c *Config) validateNatcheck(raw any) error {
	if raw != nil {
		listed, isList := raw.([]any)
		if typed, isStrings := raw.([]string); isStrings {
			for _, item := range typed {
				listed = append(listed, item)
			}
			isList = true
		}
		if !isList {
			return errorf("natcheck_addresses: expected a list of addresses")
		}
		c.NatcheckAddresses = []string{}
		for _, item := range listed {
			address, err := canonicalIP(jsonval.Str(item), "natcheck_addresses")
			if err != nil {
				return err
			}
			c.NatcheckAddresses = append(c.NatcheckAddresses, address)
		}
		if len(c.NatcheckAddresses) == 0 {
			return errorf("natcheck_addresses: give at least one address, or remove the key")
		}
	}
	if c.Natcheck && c.Mode == ModePublic {
		// nncs1 and nncs2 must be two different public IPs, each on UDP 10025 and 10125.
		single := c.NatcheckSingleIP && len(c.NatcheckAddresses) == 1
		if !single {
			if len(c.NatcheckAddresses) != 2 {
				return errorf("natcheck_addresses: public mode needs exactly two different IPs for nncs1/nncs2 (each on UDP 10025 and 10125), or natcheck=false (or one IP with natcheck_single_ip=true)")
			}
			if c.NatcheckAddresses[0] == c.NatcheckAddresses[1] {
				return errorf("natcheck_addresses: nncs1 and nncs2 cannot share one IP")
			}
		}
	}
	return nil
}

// Load reads a JSON configuration file (a UTF-8 BOM is accepted).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		var pathError *fs.PathError
		if errors.As(err, &pathError) {
			return nil, errorf("cannot read config file %s: %v", path, pathError.Err)
		}
		return nil, errorf("cannot read config file %s: %v", path, err)
	}
	data = []byte(strings.TrimPrefix(string(data), "\xef\xbb\xbf"))
	values, err := jsonval.Decode(data)
	if errors.Is(err, jsonval.ErrNotObject) {
		return nil, errorf("%s: the config file must contain a JSON object", path)
	}
	if err != nil {
		return nil, errorf("%s: invalid JSON: %v", path, err)
	}
	return New(values)
}

// Updated returns a copy with some values replaced. When the mode changes, settings that only
// had a mode-dependent default fall back to the new mode's default: `--public` must not drag the
// lab's NAT check into a public server.
func (c *Config) Updated(changes map[string]any) (*Config, error) {
	values := c.values()
	provided := map[string]bool{}
	for key := range c.provided {
		provided[key] = true
	}
	mode, hasMode := changes["mode"]
	if hasMode && strings.ToLower(strings.TrimSpace(jsonval.Str(mode))) != c.Mode {
		for _, dependent := range []string{"natcheck", "registration"} {
			if _, set := changes[dependent]; !set && !provided[dependent] {
				delete(values, dependent)
			}
		}
		if _, set := changes["listen"]; !set && !provided["listen"] {
			values["listen"] = defaultListen(jsonval.Str(mode))
		}
	}
	for key, value := range changes {
		values[key] = value
		provided[key] = true
	}
	updated, err := New(values)
	if err != nil {
		return nil, err
	}
	updated.provided = provided
	return updated, nil
}

func (c *Config) values() map[string]any {
	values := map[string]any{
		"mode": c.Mode, "listen": c.Listen, "auth_port": c.AuthPort, "secure_port": c.SecurePort,
		"natcheck": c.Natcheck, "identities": c.Identities, "accounts_db": c.AccountsDB,
		"registration": c.Registration, "fill_timeout": c.FillTimeout,
		"natcheck_single_ip": c.NatcheckSingleIP, "natcheck_same_socket": c.NatcheckSameSocket,
		"registration_proxy": c.RegistrationProxy, "random_session_key": c.RandomSessionKey,
		"integrity_mode": c.IntegrityMode, "registration_port": c.RegistrationPort,
	}
	if c.Advertise != "" {
		values["advertise"] = c.Advertise
	}
	if c.NatcheckAddresses != nil {
		values["natcheck_addresses"] = c.NatcheckAddresses
	}
	if c.HasIdentityRoots {
		values["identity_roots"] = c.IdentityRoots
	}
	if c.RegistrationToken != "" {
		values["registration_token"] = c.RegistrationToken
	}
	if c.AdminToken != "" {
		values["admin_token"] = c.AdminToken
	}
	if c.MinClientVersion != "" {
		values["min_client_version"] = c.MinClientVersion
	}
	if len(c.IntegrityReleases) > 0 {
		releases := map[string]any{}
		for version, hashes := range c.IntegrityReleases {
			releases[version] = hashes
		}
		values["integrity_releases"] = releases
	}
	return values
}

// IsPublic tells public mode from the lab.
func (c *Config) IsPublic() bool { return c.Mode == ModePublic }

// StationHost is the address written into station URLs: the advertised one, else the bound one.
func (c *Config) StationHost() string {
	if c.Advertise != "" {
		return c.Advertise
	}
	if isWildcard(c.Listen) {
		return ""
	}
	return c.Listen
}

// Describe is the one-line summary for the log (no secret).
func (c *Config) Describe() string {
	text := fmt.Sprintf("mode=%s listen=%s advertise=%s auth=%d secure=%d natcheck=%t registration=%s",
		c.Mode, c.Listen, c.StationHost(), c.AuthPort, c.SecurePort, c.Natcheck, c.Registration)
	if c.Registration != RegistrationClosed {
		text += fmt.Sprintf(":%d", c.RegistrationPort)
	}
	return text
}

func isWildcard(address string) bool {
	return address == "" || address == "0.0.0.0" || address == "::"
}

func canonicalIP(value, field string) (string, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", errorf("%s: '%s' is not an IPv4/IPv6 address", field, value)
	}
	return address.String(), nil
}

func canonicalHost(value, field string) (string, error) {
	text := strings.TrimSpace(value)
	if address, err := netip.ParseAddr(text); err == nil {
		return address.String(), nil
	}
	if text == "" || strings.ContainsAny(text, " \t\r\n/") {
		return "", errorf("%s: '%s' is not a host name or address", field, value)
	}
	return strings.ToLower(text), nil
}

func port(value any, field string) (int, error) {
	number, ok := jsonval.Int(value)
	if !ok {
		return 0, errorf("%s: '%s' is not a port number", field, jsonval.Str(value))
	}
	if number < 1 || number > 65535 {
		return 0, errorf("%s: %d is outside 1..65535", field, number)
	}
	return int(number), nil
}

// isLoopback covers 127.0.0.0/8 and localhost names: addresses that never leave this PC.
func isLoopback(value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	if text == "" {
		return false
	}
	if text == "localhost" || strings.HasSuffix(text, ".localhost") {
		return true
	}
	address, err := netip.ParseAddr(text)
	return err == nil && address.IsLoopback()
}

func strings1(value any) []string {
	result := []string{}
	switch v := value.(type) {
	case []string:
		result = append(result, v...)
	case []any:
		for _, item := range v {
			result = append(result, jsonval.Str(item))
		}
	}
	return result
}

// Flags are the command-line overrides; nil means "not given".
type Flags struct {
	ConfigFile        string
	Mode              string
	Public            bool
	Listen            string
	Advertise         string
	Port              *int
	SecurePort        *int
	Natcheck          *bool
	NatcheckAddresses []string
	Identities        []string
	IdentityRoots     []string
	AccountsDB        string
	Registration      string
	RegistrationPort  *int
	RegistrationToken string
	FillTimeout       *float64
}

// Resolve loads the file, if any, then applies the command line, which wins.
func Resolve(flags Flags) (*Config, error) {
	var (
		c   *Config
		err error
	)
	if flags.ConfigFile != "" {
		c, err = Load(flags.ConfigFile)
	} else {
		c, err = New(nil)
	}
	if err != nil {
		return nil, err
	}
	if flags.Public && flags.Mode != "" && flags.Mode != ModePublic {
		return nil, errorf("--public contradicts --mode %s", flags.Mode)
	}
	changes := map[string]any{}
	setText := func(key, value string) {
		if value != "" {
			changes[key] = value
		}
	}
	setText("mode", flags.Mode)
	if flags.Public {
		changes["mode"] = ModePublic
	}
	setText("listen", flags.Listen)
	setText("advertise", flags.Advertise)
	setText("accounts_db", flags.AccountsDB)
	setText("registration", flags.Registration)
	setText("registration_token", flags.RegistrationToken)
	if flags.Port != nil {
		changes["auth_port"] = *flags.Port
		changes["secure_port"] = *flags.Port + 1 // --port alone moves the whole pair
	}
	if flags.SecurePort != nil {
		changes["secure_port"] = *flags.SecurePort
	}
	if flags.Natcheck != nil {
		changes["natcheck"] = *flags.Natcheck
	}
	if flags.NatcheckAddresses != nil {
		changes["natcheck_addresses"] = flags.NatcheckAddresses
	}
	if flags.Identities != nil {
		changes["identities"] = flags.Identities
	}
	if flags.IdentityRoots != nil {
		changes["identity_roots"] = flags.IdentityRoots
	}
	if flags.RegistrationPort != nil {
		changes["registration_port"] = *flags.RegistrationPort
	}
	if flags.FillTimeout != nil {
		changes["fill_timeout"] = *flags.FillTimeout
	}
	return c.Updated(changes)
}
