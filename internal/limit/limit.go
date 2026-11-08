// Package limit counts events per key in a sliding window, with a bounded table.
package limit

import (
	"container/list"
	"sync"
	"time"
)

const (
	sweepAbove = 4096
	maxKeys    = 8192
)

// Clock returns seconds; the tests replace it.
type Clock func() float64

// Monotonic is the default clock.
func Monotonic() float64 { return float64(time.Now().UnixNano()) / 1e9 }

type entry struct {
	key    string
	events []float64
}

// Limiter allows at most Limit events per key inside Window seconds.
type Limiter struct {
	limit     int
	window    float64
	clock     Clock
	mu        sync.Mutex
	entries   map[string]*list.Element
	order     *list.List // oldest key first
	nextSweep float64
}

func New(limit int, window float64, clock Clock) *Limiter {
	if clock == nil {
		clock = Monotonic
	}
	return &Limiter{limit: limit, window: window, clock: clock,
		entries: map[string]*list.Element{}, order: list.New()}
}

// SetClock replaces the clock (tests).
func (l *Limiter) SetClock(clock Clock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clock = clock
}

func (l *Limiter) Allow(key string) bool {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	element, known := l.entries[key]
	if !known {
		element = l.order.PushBack(&entry{key: key})
		l.entries[key] = element
	}
	current := element.Value.(*entry)
	kept := current.events[:0]
	for _, at := range current.events {
		if now-at < l.window {
			kept = append(kept, at)
		}
	}
	current.events = kept
	if len(kept) >= l.limit {
		return false
	}
	current.events = append(current.events, now)
	l.bound(now)
	return true
}

func (l *Limiter) bound(now float64) {
	if len(l.entries) > sweepAbove && now >= l.nextSweep {
		l.nextSweep = now + 1
		for element := l.order.Front(); element != nil; {
			next := element.Next()
			current := element.Value.(*entry)
			if len(current.events) == 0 || now-current.events[len(current.events)-1] >= l.window {
				l.remove(element)
			}
			element = next
		}
	}
	for len(l.entries) > maxKeys { // a flood of fresh keys: forget the oldest
		l.remove(l.order.Front())
	}
}

func (l *Limiter) remove(element *list.Element) {
	delete(l.entries, element.Value.(*entry).key)
	l.order.Remove(element)
}

// Size is the number of keys kept (tests).
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
