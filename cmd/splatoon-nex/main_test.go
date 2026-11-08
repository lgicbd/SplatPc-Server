package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckConfigValidatesWithoutStarting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	log := filepath.Join(dir, "server.log")

	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func() (int, string) {
		var stderr bytes.Buffer
		return runServer([]string{"--config", path, "--log", log, "--check-config"}, &stderr), stderr.String()
	}

	write(`{"auth_port": 61200, "natcheck": false}`)
	if code, output := run(); code != 0 || !strings.Contains(output, "auth=61200") {
		t.Fatalf("valid config: code %d, output %q", code, output)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatalf("--check-config started the log: %v", err)
	}

	write(`{"no_such_key": 1}`)
	if code, _ := run(); code != 2 {
		t.Fatalf("unknown key: code %d, want 2", code)
	}
}
