// Package logx is the server's log: one line per event, to stderr and to a bounded rotating file.
package logx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxFileBytes = 8 * 1024 * 1024
	maxBackups   = 3
)

var (
	mu      sync.Mutex
	output  io.Writer = os.Stderr
	verbose bool
)

// Setup adds the rotating log file next to stderr. An exposed server must not fill its disk.
func Setup(path string, debug bool) error {
	verbose = debug
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := newRotatingFile(path)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	output = io.MultiWriter(os.Stderr, file)
	return nil
}

// SetOutput replaces the destination (tests).
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	output = w
}

func write(level, format string, args ...any) {
	line := fmt.Sprintf("%s nexserver %s %s\n", time.Now().Format("2006-01-02 15:04:05,000"), level, fmt.Sprintf(format, args...))
	mu.Lock()
	defer mu.Unlock()
	_, _ = io.WriteString(output, line)
}

func Debugf(format string, args ...any) {
	if verbose {
		write("DEBUG", format, args...)
	}
}

func Infof(format string, args ...any)  { write("INFO", format, args...) }
func Warnf(format string, args ...any)  { write("WARNING", format, args...) }
func Errorf(format string, args ...any) { write("ERROR", format, args...) }

type rotatingFile struct {
	path string
	file *os.File
	size int64
}

func newRotatingFile(path string) (*rotatingFile, error) {
	r := &rotatingFile{path: path}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	file, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	r.file, r.size = file, info.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	if r.size+int64(len(p)) > maxFileBytes {
		r.rotate()
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() {
	r.file.Close()
	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, maxBackups))
	for i := maxBackups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	_ = os.Rename(r.path, r.path+".1")
	if err := r.open(); err != nil {
		r.file = os.Stderr
		r.size = 0
	}
}
