package accounts

import (
	"database/sql"
	"errors"
)

// Friend requests. The friend lists themselves live on the players' PCs; the server only keeps who
// asked whom, so the other player can be told. One row per direction: (from, to).
const (
	RequestPending  = "pending"
	RequestDeclined = "declined" // created holds the day it was declined: the refusal expires
	RequestAccepted = "accepted"
)

const createFriendRequests = `CREATE TABLE IF NOT EXISTS friend_requests (
	from_pid INTEGER NOT NULL, to_pid INTEGER NOT NULL, created REAL NOT NULL, state TEXT NOT NULL,
	PRIMARY KEY (from_pid, to_pid))`

const createFriendRequestsIndex = `CREATE INDEX IF NOT EXISTS friend_requests_to ON friend_requests(to_pid, state, created)`

// FriendRequest is one row of friend_requests.
type FriendRequest struct {
	From, To uint32
	Created  float64
	State    string
}

// GetRequest is the request from -> to; false when there is none.
func (s *Store) GetRequest(from, to uint32) (FriendRequest, bool, error) {
	request := FriendRequest{From: from, To: to}
	err := s.handle().QueryRow(`SELECT created, state FROM friend_requests WHERE from_pid = ? AND to_pid = ?`,
		from, to).Scan(&request.Created, &request.State)
	if errors.Is(err, sql.ErrNoRows) {
		return request, false, nil
	}
	return request, err == nil, err
}

// SetRequest creates or replaces the request from -> to.
func (s *Store) SetRequest(from, to uint32, state string, created float64) error {
	_, err := s.handle().Exec(`INSERT INTO friend_requests (from_pid, to_pid, created, state) VALUES (?, ?, ?, ?)
		ON CONFLICT(from_pid, to_pid) DO UPDATE SET created = excluded.created, state = excluded.state`,
		from, to, created, state)
	return err
}

// DeleteRequest drops the request from -> to when it is in one of the given states.
func (s *Store) DeleteRequest(from, to uint32, states ...string) error {
	for _, state := range states {
		if _, err := s.handle().Exec(`DELETE FROM friend_requests WHERE from_pid = ? AND to_pid = ? AND state = ?`,
			from, to, state); err != nil {
			return err
		}
	}
	return nil
}

// CountPending is how many pending requests this player sent (sent) or received (not sent).
func (s *Store) CountPending(pid uint32, sent bool) (int, error) {
	column := "to_pid"
	if sent {
		column = "from_pid"
	}
	var count int
	err := s.handle().QueryRow(`SELECT COUNT(*) FROM friend_requests WHERE `+column+` = ? AND state = ?`,
		pid, RequestPending).Scan(&count)
	return count, err
}

// PendingFor lists the senders of the pending requests this player received, oldest first.
func (s *Store) PendingFor(pid uint32, limit int) ([]uint32, error) {
	rows, err := s.handle().Query(`SELECT from_pid FROM friend_requests WHERE to_pid = ? AND state = ?
		ORDER BY created, from_pid LIMIT ?`, pid, RequestPending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var senders []uint32
	for rows.Next() {
		var sender uint32
		if err := rows.Scan(&sender); err != nil {
			return nil, err
		}
		senders = append(senders, sender)
	}
	return senders, rows.Err()
}

// DeleteRequestsOf forgets every request sent by or to this player (a ban, an erased account).
func (s *Store) DeleteRequestsOf(pid uint32) error {
	_, err := s.handle().Exec(`DELETE FROM friend_requests WHERE from_pid = ? OR to_pid = ?`, pid, pid)
	return err
}
