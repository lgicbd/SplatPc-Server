package matchmake

import (
	"net/netip"
	"testing"

	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
	"github.com/lgicbd/SplatPc-Server/internal/station"
)

func TestWireGuardStationNeverLeaksRealIP(t *testing.T) {
	discardLogs(t)
	m := New(Options{
		Public:          true,
		LANPublic:       "198.51.100.9",
		WireGuardSubnet: netip.MustParsePrefix("10.66.0.0/16"),
	})

	conn, _ := connection(m, 0x10000001, "10.66.0.2:45000")
	registered := url(t, "prudp:/address=192.168.1.55;port=10000;type=2")

	// Client attempts to register a real LAN IP (192.168.1.55).
	out := nexstream.NewWriter(true)
	if err := m.register(conn, []*station.URL{registered}, out); err != nil {
		t.Fatalf("register: %v", err)
	}

	for _, st := range m.stations[0x10000001] {
		if got := st.Get("address"); got != "10.66.0.2" {
			t.Fatalf("leaked non-WireGuard address %q in station %s", got, st)
		}
	}

	// ReplaceURL attempting to inject a real public IP must also be pinned to 10.66.0.2.
	replace := params(func(out *nexstream.Writer) {
		out.Text(registered.String())
		out.Text("prudp:/address=203.0.113.77;port=51234;type=3;natf=1;natm=1")
	})
	if err := m.handleReplaceURL(conn, replace, nexstream.NewWriter(true)); err != nil {
		t.Fatalf("handleReplaceURL: %v", err)
	}
	for _, st := range m.stations[0x10000001] {
		if got := st.Get("address"); got != "10.66.0.2" {
			t.Fatalf("ReplaceURL leaked address %q in station %s", got, st)
		}
		if st.Int("type") == urlTypePublic && st.Int("port") != 51234 {
			t.Fatalf("expected replaced port 51234, got %d", st.Int("port"))
		}
	}
}
