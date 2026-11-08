package nex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/limit"
	"github.com/lgicbd/SplatPc-Server/internal/rmc"
)

func refusedAs(t *testing.T, err error, code uint32) {
	t.Helper()
	var refused *rmc.Error
	if !errors.As(err, &refused) || refused.Code != code {
		t.Fatalf("err = %v", err)
	}
}

func TestConnectionLimits(t *testing.T) {
	limiter := newConnectionLimiter(3, 2)
	for i, step := range []struct {
		ip   string
		want bool
	}{{"a", true}, {"a", true}, {"a", false}, {"b", true}, {"c", false}} {
		if limiter.enter(step.ip) != step.want {
			t.Fatalf("step %d", i)
		}
	}
	limiter.leave("a")
	if !limiter.enter("c") {
		t.Fatal("a slot was freed")
	}
	if limiter.total != 3 {
		t.Fatalf("%d in use", limiter.total)
	}
}

func TestRefusalLoggingIsThrottledPerAddress(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := newConnectionLimiter(1, 1)
	limiter.now = func() time.Time { return now }
	if !limiter.shouldLogRefusal("ip") || limiter.shouldLogRefusal("ip") || !limiter.shouldLogRefusal("other") {
		t.Fatal("once per address")
	}
	now = now.Add(refusalLogPeriod + time.Second)
	if !limiter.shouldLogRefusal("ip") {
		t.Fatal("the period is over")
	}
}

func TestUsernames(t *testing.T) {
	for _, name := range []string{"", "abc", "0", "-1", "99999999999", strings.Repeat("1", 5000)} {
		if _, err := parseUsername(name); err == nil {
			t.Fatalf("%.20q accepted", name)
		} else {
			refusedAs(t, err, rmc.InvalidUsername)
		}
	}
	if pid, err := parseUsername("4097"); err != nil || pid != 4097 {
		t.Fatalf("pid %d, err %v", pid, err)
	}
}

func TestLoginFloodIsRefusedPerAddress(t *testing.T) {
	identity := filepath.Join(t.TempDir(), "identity.ini")
	if err := os.WriteFile(identity, []byte("pid = 00001001\npassword = 0000100100001001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &auth{identities: []string{identity}, ipRate: limit.New(2, rateWindow, nil), pidRate: limit.New(10, rateWindow, nil)}
	for i := 0; i < 2; i++ {
		if _, err := service.userKey(0x1001, "203.0.113.1"); err != nil {
			t.Fatal(err)
		}
	}
	_, err := service.userKey(0x1001, "203.0.113.1")
	refusedAs(t, err, rmc.InvalidUsername)
	if _, err := service.userKey(0x1001, "203.0.113.2"); err != nil {
		t.Fatal("another address is not affected")
	}
}

func TestTicketFloodDoesNotLockThePlayerOutFromElsewhere(t *testing.T) {
	identity := filepath.Join(t.TempDir(), "identity.ini")
	if err := os.WriteFile(identity, []byte("pid = 00001001\npassword = 0000100100001001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &auth{identities: []string{identity}, ipRate: limit.New(10, rateWindow, nil), pidRate: limit.New(1, rateWindow, nil)}
	if _, err := service.userKey(0x1001, "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.userKey(0x1001, "203.0.113.1"); err == nil {
		t.Fatal("too many tickets")
	}
	if _, err := service.userKey(0x1001, "203.0.113.2"); err != nil {
		t.Fatal("a stranger must not lock the pid out")
	}
}
