package matchmake

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
	"github.com/lgicbd/SplatPc-Server/internal/station"
)

const (
	protocolSecure = 11
	urlTypePublic  = 3
	reportLogBytes = 32
)

func readStations(in *nexstream.Reader) []*station.URL {
	texts := in.Strings()
	urls := make([]*station.URL, 0, len(texts))
	for _, text := range texts {
		if in.Err() != nil {
			break
		}
		url, err := station.Parse(text)
		if err != nil {
			in.Fail()
			break
		}
		urls = append(urls, url)
	}
	return urls
}

func readStation(in *nexstream.Reader) *station.URL {
	url, err := station.Parse(in.Text())
	if err != nil {
		in.Fail()
	}
	return url
}

func writeStations(out *nexstream.Writer, urls []*station.URL) {
	out.U32(uint32(len(urls)))
	for _, url := range urls {
		out.Text(url.String())
	}
}

// IsPrivate is true for an address that is not reachable from the Internet.
func IsPrivate(host string) bool {
	address, err := netip.ParseAddr(host)
	return err == nil && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast())
}

func (m *Matchmaker) secureMethods() rmc.Methods {
	return rmc.Methods{
		1: m.handleRegister,
		4: m.handleRegisterEx,
		7: m.handleReplaceURL,
		8: m.handleSendReport,
	}
}

func (m *Matchmaker) handleRegister(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	urls := readStations(in)
	if err := in.Err(); err != nil {
		return err
	}
	return m.register(c, urls, out)
}

func (m *Matchmaker) handleRegisterEx(c *rmc.Conn, in *nexstream.Reader, out *nexstream.Writer) error {
	urls := readStations(in)
	in.AnyData() // the login data: nothing depends on it
	if err := in.Err(); err != nil {
		return err
	}
	return m.register(c, urls, out)
}

func (m *Matchmaker) register(c *rmc.Conn, urls []*station.URL, out *nexstream.Writer) error {
	pid := c.PID()
	source := c.RemoteAddr()
	host, port := source.Addr().String(), int(source.Port())
	logx.Infof("Register pid=%08x urls=%v", pid, urls)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectionID++
	public := station.New("prudp")
	if len(urls) > 0 {
		public = urls[0].Copy()
	}
	if !m.options.Public && strings.HasPrefix(host, "127.") {
		// Same-PC lab: every game shows 127.0.0.1, and a PIA host refuses a newcomer with its own
		// public IP and no private address ("match full"). Each player gets its own loopback IP.
		known, found := m.publicIPs[pid]
		if !found {
			known = fmt.Sprintf("127.0.0.%d", 10+len(m.publicIPs))
			m.publicIPs[pid] = known
		}
		host = known
		m.fakeIPs[host] = true
	}
	publicHost := host
	if m.options.Public && m.options.LANPublic != "" && IsPrivate(host) {
		publicHost = m.options.LANPublic // behind the same router as the server: peers need the router's address
	}
	public.Set("address", publicHost)
	public.SetInt("port", port)
	public.SetInt("type", urlTypePublic)
	public.SetInt("RVCID", int(m.connectionID))

	// A login is a new session: forget what the previous connection left, even if it died silently.
	delete(m.natPorts, pid)
	m.forgetAddresses(pid)
	if m.live[pid] != nil {
		m.live[pid] = map[*rmc.Conn]bool{c: true}
	}
	m.byRVCID[m.connectionID] = pid
	m.clients[pid] = c

	stations := make([]*station.URL, 0, len(urls)+1)
	for _, url := range urls {
		copied := url.Copy()
		address := copied.Get("address")
		// The game registers its local address: peers cannot use it, and PIA may prefer it.
		if m.options.Public && (address == "" || address == "0.0.0.0" || strings.HasPrefix(address, "127.")) {
			copied.Set("address", host)
		}
		stations = append(stations, copied)
	}
	m.stations[pid] = append(stations, public)

	out.U32(rmc.Success)
	out.U32(m.connectionID)
	out.Text(public.String())
	return nil
}

// handleReplaceURL: once its PIA socket exists the game swaps its registered URL for the PIA one.
func (m *Matchmaker) handleReplaceURL(c *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	url := readStation(in)
	replacement := readStation(in)
	if err := in.Err(); err != nil {
		return err
	}
	pid := c.PID()
	logx.Infof("ReplaceURL pid=%08x %s -> %s", pid, url, replacement)
	m.mu.Lock()
	defer m.mu.Unlock()
	stations := m.stations[pid]
	// On port and type: in public mode the stored address was rewritten. The list must keep 1 or 2
	// URLs, or PIA refuses it.
	replaced := false
	for i, old := range stations {
		if old.Int("port") == url.Int("port") && old.Int("type") == url.Int("type") {
			updated := replacement.Copy()
			if m.options.Public && strings.HasPrefix(updated.Get("address"), "127.") {
				updated.Set("address", c.RemoteAddr().Addr().String())
			}
			stations[i] = updated
			replaced = true
			break
		}
	}
	if !replaced {
		logx.Warnf("  ReplaceURL: no registered URL matches, list kept")
		return nil
	}
	if m.options.Public {
		// The public URL still names the NEX socket the game logged in from; peers must reach its
		// PIA socket. The router is assumed to keep the port until the NAT check says otherwise.
		for _, item := range stations {
			if item.Int("type") != urlTypePublic {
				continue
			}
			port, measured := m.natPorts[pid]
			if !measured {
				port = replacement.Int("port")
			}
			item.SetInt("port", port)
			for _, field := range []string{"natf", "natm", "pmp", "upnp"} {
				item.SetInt(field, replacement.Int(field))
			}
		}
	}
	return nil
}

func (m *Matchmaker) handleSendReport(_ *rmc.Conn, in *nexstream.Reader, _ *nexstream.Writer) error {
	id := in.U32()
	data := in.QBuffer()
	if err := in.Err(); err != nil {
		return err
	}
	head, more := data, ""
	if len(head) > reportLogBytes { // the body can be large and may carry player data
		head, more = head[:reportLogBytes], "..."
	}
	logx.Infof("SendReport id=%d bytes=%d data=%s%s", id, len(data), hex.EncodeToString(head), more)
	return nil
}
