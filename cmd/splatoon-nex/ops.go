package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const opsTimeout = 10 * time.Second

func opsRequest(base, token, path string, body any) (int, any) {
	var (
		method  = http.MethodGet
		payload io.Reader
	)
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, map[string]any{"error": err.Error()}
		}
		method, payload = http.MethodPost, bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, strings.TrimRight(base, "/")+path, payload)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: opsTimeout}).Do(request)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return response.StatusCode, map[string]any{"error": response.Status}
	}
	return response.StatusCode, decoded
}

// optional is a flag whose absence reaches the JSON as null.
func optional(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func runOps(args []string, stdout, stderr io.Writer) int {
	base := os.Getenv("SPLATOON_OPS_URL")
	if base == "" {
		base = "http://127.0.0.1:60002"
	}
	global := flag.NewFlagSet("ops", flag.ContinueOnError)
	global.SetOutput(stderr)
	global.StringVar(&base, "url", base, "endpoint base URL")
	token := global.String("token", os.Getenv("SPLATOON_REGISTER_TOKEN"), "admin token")
	if err := global.Parse(args); err != nil {
		return 2
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: splatoon-nex ops [--url URL] [--token TOKEN] metrics|sessions|kick PID|ban|unban|bans|log")
		return 2
	}
	var (
		status  int
		payload any
	)
	command := rest[0]
	switch command {
	case "metrics":
		status, payload = opsRequest(base, "", "/metrics", nil)
	case "sessions", "bans", "log":
		status, payload = opsRequest(base, *token, "/admin/"+command, nil)
	case "kick":
		if len(rest) != 2 {
			fmt.Fprintln(stderr, "kick: give the player id")
			return 2
		}
		status, payload = opsRequest(base, *token, "/admin/kick?pid="+url.QueryEscape(rest[1]), nil)
	case "ban", "unban":
		body, err := parseBan(command, rest[1:], stderr)
		if err != nil {
			return 2
		}
		status, payload = opsRequest(base, *token, "/admin/"+command, body)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", command)
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if status != http.StatusOK {
		return 1
	}
	return 0
}

func parseBan(command string, args []string, stderr io.Writer) (map[string]any, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	pid := fs.String("pid", "", "principal id (decimal or 0x-hex)")
	ip := fs.String("ip", "", "source address")
	var hours *float64
	reason := ""
	if command == "ban" {
		fs.Func("hours", "ban for this many hours (default: for good)", func(value string) error {
			var parsed float64
			if _, err := fmt.Sscanf(value, "%g", &parsed); err != nil {
				return err
			}
			hours = &parsed
			return nil
		})
		fs.StringVar(&reason, "reason", "", "short reason, kept in the moderation log")
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *pid == "" && *ip == "" {
		fmt.Fprintf(stderr, "%s: give --pid and/or --ip\n", command)
		return nil, errors.New("no target")
	}
	body := map[string]any{"pid": optional(*pid), "ip": optional(*ip)}
	if command == "ban" {
		body["reason"] = reason
		body["hours"] = nil
		if hours != nil {
			body["hours"] = *hours
		}
	}
	return body, nil
}
