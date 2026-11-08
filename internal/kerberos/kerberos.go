// Package kerberos is NEX's ticket encryption: RC4 followed by an HMAC-MD5 of the ciphertext.
package kerberos

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"time"

	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
)

const (
	checksumSize = 16
	// SessionKeySize is the size of the keys in tickets.
	SessionKeySize = 32
)

// ErrChecksum is a ticket that was not encrypted with this key.
var ErrChecksum = errors.New("invalid Kerberos checksum")

func applyRC4(key, data []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(data))
	cipher.XORKeyStream(output, data)
	return output, nil
}

func mac(key, data []byte) []byte {
	digest := hmac.New(md5.New, key)
	digest.Write(data)
	return digest.Sum(nil)
}

// Encrypt returns the ciphertext and its checksum.
func Encrypt(key, data []byte) ([]byte, error) {
	encrypted, err := applyRC4(key, data)
	if err != nil {
		return nil, err
	}
	return append(encrypted, mac(key, encrypted)...), nil
}

// Decrypt checks the checksum and returns the clear data.
func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < checksumSize {
		return nil, ErrChecksum
	}
	body, checksum := data[:len(data)-checksumSize], data[len(data)-checksumSize:]
	if !hmac.Equal(checksum, mac(key, body)) {
		return nil, ErrChecksum
	}
	return applyRC4(key, body)
}

// RandomBytes is a fresh secret.
func RandomBytes(size int) []byte {
	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		panic(err) // the system has no randomness left: nothing can be done safely
	}
	return secret
}

func derivedKey(key, ticketKey []byte) []byte {
	sum := md5.Sum(append(append([]byte(nil), key...), ticketKey...))
	return sum[:]
}

// ServerTicket is what only the secure server can read: who the ticket is for, and when it was made.
type ServerTicket struct {
	Timestamp  time.Time
	Source     uint32
	SessionKey []byte
}

// Encrypt writes the version 1 form: a random key mixed with the secure server's key.
func (t ServerTicket) Encrypt(key []byte) ([]byte, error) {
	clear := nexstream.NewWriter(false)
	clear.U64(nexstream.DateTime(t.Timestamp))
	clear.PID(t.Source)
	clear.Write(t.SessionKey)
	ticketKey := RandomBytes(16)
	encrypted, err := Encrypt(derivedKey(key, ticketKey), clear.Bytes())
	if err != nil {
		return nil, err
	}
	out := nexstream.NewWriter(false)
	out.Buffer(ticketKey)
	out.Buffer(encrypted)
	return out.Bytes(), nil
}

// DecryptServerTicket reverses ServerTicket.Encrypt.
func DecryptServerTicket(data, key []byte) (*ServerTicket, error) {
	in := nexstream.NewReader(data, false)
	ticketKey := in.Buffer()
	encrypted := in.Buffer()
	if err := in.Err(); err != nil {
		return nil, err
	}
	clear, err := Decrypt(derivedKey(key, ticketKey), encrypted)
	if err != nil {
		return nil, err
	}
	body := nexstream.NewReader(clear, false)
	ticket := &ServerTicket{Timestamp: nexstream.Time(body.U64()), Source: body.PID()}
	ticket.SessionKey = append([]byte(nil), body.Read(SessionKeySize)...)
	return ticket, body.Err()
}

// ClientTicket is what the player reads with its own key.
type ClientTicket struct {
	SessionKey []byte
	Target     uint32
	Internal   []byte
}

// Encrypt encrypts the ticket with the player's key.
func (t ClientTicket) Encrypt(key []byte) ([]byte, error) {
	clear := nexstream.NewWriter(false)
	clear.Write(t.SessionKey)
	clear.PID(t.Target)
	clear.Buffer(t.Internal)
	return Encrypt(key, clear.Bytes())
}
