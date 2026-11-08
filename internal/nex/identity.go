package nex

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	identityFile   = "online_identity.ini"
	passwordLength = 16
	maxIdentityPID = 0x7FFFFFFF
)

// DefaultIdentityRoots are searched in lab mode, relative to the working directory.
var DefaultIdentityRoots = []string{"Game", "build/benchmarks"}

func isAlphanumeric(text string) bool {
	for _, c := range []byte(text) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func readIdentity(path string) (uint32, string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", false
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if key, value, found := strings.Cut(line, "="); found {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	number, err := strconv.ParseUint(fields["pid"], 16, 32)
	password := fields["password"]
	if err != nil || number == 0 || number > maxIdentityPID || len(password) != passwordLength || !isAlphanumeric(password) {
		return 0, "", false
	}
	return uint32(number), password, true
}

// findPassword returns the newest valid identity of a player; corrupt candidates are skipped.
func findPassword(pid uint32, files, roots []string) (string, bool) {
	candidates := append([]string(nil), files...)
	for _, root := range roots {
		candidates = append(candidates, filepath.Join(root, identityFile))
		nested, _ := filepath.Glob(filepath.Join(root, "*", identityFile))
		candidates = append(candidates, nested...)
	}
	type dated struct {
		path string
		time int64
	}
	var existing []dated
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil {
			existing = append(existing, dated{path, info.ModTime().UnixNano()})
		}
	}
	sort.Slice(existing, func(i, j int) bool { return existing[i].time > existing[j].time })
	for _, candidate := range existing {
		if found, password, valid := readIdentity(candidate.path); valid && found == pid {
			return password, true
		}
	}
	return "", false
}
