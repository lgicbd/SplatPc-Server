package limit

import (
	"fmt"
	"testing"
)

func TestWindowIsPerKeyAndSlides(t *testing.T) {
	now := 1000.0
	limiter := New(2, 60, func() float64 { return now })
	for i, want := range []bool{true, true, false} {
		if limiter.Allow("ip") != want {
			t.Fatalf("call %d", i)
		}
	}
	if !limiter.Allow("other") {
		t.Fatal("another key is not affected")
	}
	now += 61
	if !limiter.Allow("ip") {
		t.Fatal("a new window starts")
	}
}

func TestTableStaysBoundedUnderAFloodOfNewKeys(t *testing.T) {
	limiter := New(5, 60, nil)
	for i := 0; i < 20000; i++ {
		if !limiter.Allow(fmt.Sprintf("198.51.%d.%d", i/250, i%250)) {
			t.Fatalf("key %d refused", i)
		}
	}
	if limiter.Size() > maxKeys {
		t.Fatalf("%d keys", limiter.Size())
	}
	for i := 0; i < 5; i++ {
		limiter.Allow("203.0.113.1")
	}
	if limiter.Allow("203.0.113.1") {
		t.Fatal("a real offender is still limited")
	}
}
