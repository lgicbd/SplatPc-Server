package social

import (
	"fmt"
	"strconv"

	"github.com/lgicbd/SplatPc-Server/internal/accounts"
	"github.com/lgicbd/SplatPc-Server/internal/jsonval"
	"github.com/lgicbd/SplatPc-Server/internal/limit"
	"github.com/lgicbd/SplatPc-Server/internal/logx"
)

// Friend requests. The lists stay on the players' PCs and presence stays mutual-only: a request only
// tells the other player that someone wants to be listed. Whoever sends one is already listed on
// their own PC, so accepting (listing the sender back) makes the two lists mutual.
const (
	MaxPendingSent     = 20
	MaxPendingReceived = 50
	DeclineTTL         = 30 * 86400.0 // a refusal blocks the same request this long, then the sender may ask again
)

// Request is a pending friend request received.
type Request struct {
	PID  string `json:"pid"`
	Name string `json:"name"`
}

func (s *Social) requestRefused(token string, rate *limit.Limiter) (uint32, error) {
	pid := s.PIDOf(token)
	if pid == 0 {
		return 0, &Error{401, "session expired"}
	}
	if err := s.refuseBanned(pid); err != nil {
		return 0, err
	}
	if !rate.Allow(strconv.FormatUint(uint64(pid), 10)) {
		return 0, &Error{429, "too many requests, wait a moment"}
	}
	return pid, nil
}

func internalFailure(what string, err error) error {
	logx.Errorf("%s failed: %v", what, err)
	return &Error{500, "internal error"}
}

// SendRequest asks target to be a friend. The answer never tells whether the target exists, is
// banned, is full or refused before: "sent" in all those cases, "friends" when the target had
// already asked this player (then the two lists become mutual at once).
func (s *Social) SendRequest(token string, target any) (map[string]string, error) {
	pid, err := s.requestRefused(token, s.RequestRate)
	if err != nil {
		return nil, err
	}
	other, valid := parseFriend(target)
	if !valid {
		return nil, &Error{400, "invalid player"}
	}
	if other == pid {
		return nil, &Error{400, "you cannot add yourself"}
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	store := s.Accounts
	own, err := store.PseudoOf(pid)
	if err != nil {
		return nil, internalFailure("pseudo read", err)
	}
	if own == "" {
		return nil, &Error{400, "choose a pseudo first"}
	}
	sent := map[string]string{"state": "sent"}
	name, err := store.PseudoOf(other)
	if err != nil {
		return nil, internalFailure("pseudo read", err)
	}
	banned, err := store.IsBanned(&other, "")
	if err != nil {
		return nil, internalFailure("ban check", err)
	}
	if name == "" || banned {
		return sent, nil
	}

	_, asked, err := store.GetRequest(other, pid)
	if err != nil {
		return nil, internalFailure("request read", err)
	}
	if asked { // they already asked this player (pending, refused, or accepted): the lists are mutual now
		if err := store.SetRequest(other, pid, accounts.RequestAccepted, s.Clock()); err != nil {
			return nil, internalFailure("request write", err)
		}
		if err := store.DeleteRequest(pid, other, accounts.RequestPending, accounts.RequestDeclined); err != nil {
			return nil, internalFailure("request write", err)
		}
		return map[string]string{"state": "friends"}, nil
	}

	now := s.Clock()
	forward, exists, err := store.GetRequest(pid, other)
	if err != nil {
		return nil, internalFailure("request read", err)
	}
	if exists {
		switch {
		case forward.State == accounts.RequestAccepted:
			return map[string]string{"state": "friends"}, nil
		case forward.State == accounts.RequestPending:
			return sent, nil
		case now-forward.Created < DeclineTTL: // refused lately: silent, nothing changes
			return sent, nil
		}
	}
	mine, err := store.CountPending(pid, true)
	if err != nil {
		return nil, internalFailure("request count", err)
	}
	if mine >= MaxPendingSent {
		return nil, &Error{429, fmt.Sprintf("too many pending requests (%d), wait for answers", MaxPendingSent)}
	}
	theirs, err := store.CountPending(other, false)
	if err != nil {
		return nil, internalFailure("request count", err)
	}
	if theirs >= MaxPendingReceived { // their box is full: silent
		return sent, nil
	}
	if err := store.SetRequest(pid, other, accounts.RequestPending, now); err != nil {
		return nil, internalFailure("request write", err)
	}
	return sent, nil
}

// AnswerRequest accepts or refuses the pending request from sender. A refusal is silent for the
// sender and lasts DeclineTTL.
func (s *Social) AnswerRequest(token string, sender, accept any) error {
	pid, err := s.requestRefused(token, s.AnswerRate)
	if err != nil {
		return err
	}
	other, valid := parseFriend(sender)
	if !valid {
		return &Error{400, "invalid player"}
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	request, pending, err := s.Accounts.GetRequest(other, pid)
	if err != nil {
		return internalFailure("request read", err)
	}
	if !pending || request.State != accounts.RequestPending {
		return &Error{404, "no such request"}
	}
	state := accounts.RequestDeclined
	if jsonval.Truthy(accept) {
		state = accounts.RequestAccepted
	}
	now := s.Clock()
	if err := s.Accounts.SetRequest(other, pid, state, now); err != nil {
		return internalFailure("request write", err)
	}
	if state == accounts.RequestAccepted { // they had asked too: nothing left to wait for
		if err := s.Accounts.DeleteRequest(pid, other, accounts.RequestPending); err != nil {
			return internalFailure("request write", err)
		}
	}
	return nil
}

// CancelRequest is "I removed this player from my list": a pending request to them is withdrawn
// and an accepted one is forgotten, so a later request starts again. A refusal stays (it protects
// the one who refused).
func (s *Social) CancelRequest(token string, target any) error {
	pid, err := s.requestRefused(token, s.AnswerRate)
	if err != nil {
		return err
	}
	other, valid := parseFriend(target)
	if !valid {
		return &Error{400, "invalid player"}
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	if err := s.Accounts.DeleteRequest(pid, other, accounts.RequestPending, accounts.RequestAccepted); err != nil {
		return internalFailure("request write", err)
	}
	if err := s.Accounts.DeleteRequest(other, pid, accounts.RequestAccepted); err != nil {
		return internalFailure("request write", err)
	}
	return nil
}

// PendingRequests lists the requests this player received and has not answered.
func (s *Social) PendingRequests(token string) ([]Request, error) {
	pid := s.PIDOf(token)
	if pid == 0 {
		return nil, &Error{401, "session expired"}
	}
	senders, err := s.Accounts.PendingFor(pid, MaxPendingReceived)
	if err != nil {
		return nil, internalFailure("request read", err)
	}
	names, err := s.Accounts.PseudosFor(senders)
	if err != nil {
		return nil, internalFailure("pseudo read", err)
	}
	result := make([]Request, 0, len(senders))
	for _, sender := range senders {
		name, named := names[sender]
		if !named {
			name = "Ami"
		}
		result = append(result, Request{fmt.Sprintf("%08x", sender), name})
	}
	return result, nil
}
