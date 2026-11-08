// Package station handles NEX station URLs: `scheme:/key=value;key=value`, in a kept order.
package station

import (
	"errors"
	"strconv"
	"strings"
)

// ErrInvalid is a URL that does not have the expected shape.
var ErrInvalid = errors.New("invalid station URL")

type param struct{ key, value string }

// URL is a parsed station URL.
type URL struct {
	Scheme string
	params []param
}

// New is an empty URL.
func New(scheme string) *URL { return &URL{Scheme: scheme} }

// Parse reads a URL; the empty string is an empty prudp URL.
func Parse(text string) (*URL, error) {
	if text == "" {
		return New("prudp"), nil
	}
	scheme, fields, found := strings.Cut(text, ":/")
	if !found || strings.Contains(fields, ":/") {
		return nil, ErrInvalid
	}
	url := New(scheme)
	if fields == "" {
		return url, nil
	}
	for _, field := range strings.Split(fields, ";") {
		key, value, found := strings.Cut(field, "=")
		if !found || strings.Contains(value, "=") {
			return nil, ErrInvalid
		}
		url.Set(key, value)
	}
	return url, nil
}

func (u *URL) String() string {
	parts := make([]string, len(u.params))
	for i, item := range u.params {
		parts[i] = item.key + "=" + item.value
	}
	return u.Scheme + ":/" + strings.Join(parts, ";")
}

// Copy is an independent URL.
func (u *URL) Copy() *URL {
	return &URL{Scheme: u.Scheme, params: append([]param(nil), u.params...)}
}

// Get returns a value, "" when absent.
func (u *URL) Get(key string) string {
	for _, item := range u.params {
		if item.key == key {
			return item.value
		}
	}
	return ""
}

// Int returns a number, 0 when absent or not a number.
func (u *URL) Int(key string) int {
	number, err := strconv.Atoi(u.Get(key))
	if err != nil {
		return 0
	}
	return number
}

// Set replaces a value in place, or appends it.
func (u *URL) Set(key, value string) {
	for i := range u.params {
		if u.params[i].key == key {
			u.params[i].value = value
			return
		}
	}
	u.params = append(u.params, param{key, value})
}

// SetInt is Set for a number.
func (u *URL) SetInt(key string, value int) { u.Set(key, strconv.Itoa(value)) }
