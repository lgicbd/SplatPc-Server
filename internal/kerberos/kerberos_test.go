package kerberos

import (
	"bytes"
	"testing"
	"time"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef")
	sealed, err := Encrypt(key, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	clear, err := Decrypt(key, sealed)
	if err != nil || string(clear) != "message" {
		t.Fatalf("got %q, %v", clear, err)
	}
	if _, err := Decrypt([]byte("another-key-here"), sealed); err != ErrChecksum {
		t.Fatalf("wrong key: %v", err)
	}
	sealed[0] ^= 1
	if _, err := Decrypt(key, sealed); err != ErrChecksum {
		t.Fatalf("altered data: %v", err)
	}
	if _, err := Decrypt(key, []byte{1, 2}); err != ErrChecksum {
		t.Fatalf("short data: %v", err)
	}
}

func TestServerTicketRoundTrip(t *testing.T) {
	key := RandomBytes(16)
	sessionKey := RandomBytes(SessionKeySize)
	moment := time.Date(2026, 11, 8, 1, 2, 3, 0, time.UTC)
	sealed, err := ServerTicket{Timestamp: moment, Source: 0x1234, SessionKey: sessionKey}.Encrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := DecryptServerTicket(sealed, key)
	if err != nil {
		t.Fatal(err)
	}
	if !ticket.Timestamp.Equal(moment) || ticket.Source != 0x1234 || !bytes.Equal(ticket.SessionKey, sessionKey) {
		t.Fatalf("ticket = %+v", ticket)
	}
	if _, err := DecryptServerTicket(sealed, RandomBytes(16)); err == nil {
		t.Fatal("another key must not open the ticket")
	}
	if _, err := DecryptServerTicket([]byte{1}, key); err == nil {
		t.Fatal("garbage must not open")
	}
}
