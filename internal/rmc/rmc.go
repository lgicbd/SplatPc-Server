// Package rmc is NEX's remote method call layer over a PRUDP connection.
package rmc

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/lgicbd/SplatPc-Server/internal/logx"
	"github.com/lgicbd/SplatPc-Server/internal/nexstream"
)

// Result codes the server answers with.
const (
	Success            = 0x00010001
	CoreNotImplemented = 0x80010002
	CoreException      = 0x80010005

	InvalidUsername  = 0x80030064
	SessionVoid      = 0x80030073
	SessionFull      = 0x800300C8
	PermissionDenied = 0x800300D9
	SessionClosed    = 0x800300DB

	requestFlag  = 0x80
	responseFlag = 0x8000
	extendedID   = 0x7F

	maxLoggedParams = 256 // of a request a handler could not read
)

// Error is a refusal a handler sends back to the caller.
type Error struct{ Code uint32 }

func (e *Error) Error() string { return fmt.Sprintf("RMC error %08x", e.Code) }

// Transport is the connection under RMC.
type Transport interface {
	Recv() ([]byte, bool)
	Send(data []byte) error
	Close()
	PID() uint32
	MinorVersion() uint8
	RemoteAddr() netip.AddrPort
}

// Handler serves one method: it reads its parameters from in, and its answer goes to out.
type Handler func(conn *Conn, in *nexstream.Reader, out *nexstream.Writer) error

// Methods maps method ids to handlers.
type Methods map[uint32]Handler

// Services maps protocol ids to their methods.
type Services map[uint16]Methods

// Conn is one RMC connection.
type Conn struct {
	Transport
	services     Services
	structHeader bool
	nextCall     atomic.Uint32
	mu           sync.Mutex
}

// NewConn prepares a connection for Run.
func NewConn(transport Transport, services Services) *Conn {
	conn := &Conn{Transport: transport, services: services, structHeader: transport.MinorVersion() >= 3}
	conn.nextCall.Store(1)
	return conn
}

// ErrMalformed is a message that cannot be an RMC call: it ends the connection.
var ErrMalformed = errors.New("malformed RMC message")

var failures atomic.Uint64

// Failures counts the unexpected errors since the start, for the operators.
func Failures() uint64 { return failures.Load() }

// Run answers requests one at a time until the connection ends. A malformed message ends it.
func (c *Conn) Run() {
	for {
		message, alive := c.Recv()
		if !alive {
			return
		}
		if err := c.dispatch(message); err != nil {
			logx.Warnf("RMC from %s: %v", c.RemoteAddr(), err)
			failures.Add(1)
			c.Close()
			return
		}
	}
}

func (c *Conn) dispatch(message []byte) error {
	in := nexstream.NewReader(message, c.structHeader)
	size := in.U32()
	if in.Err() != nil || int(size) != in.Remaining() {
		return ErrMalformed
	}
	first := in.U8()
	request := first&requestFlag != 0
	protocol := uint16(first &^ requestFlag)
	if protocol == extendedID {
		protocol = in.U16()
	}
	if in.Err() != nil {
		return ErrMalformed
	}
	if !request {
		return nil // the answer to a notification: nothing waits for it
	}
	call := in.U32()
	method := in.U32()
	if in.Err() != nil {
		return ErrMalformed
	}
	logx.Debugf("RMC request protocol=%d method=%d params=%d", protocol, method, in.Remaining())
	out := nexstream.NewWriter(c.structHeader)
	code := c.call(protocol, method, in, out)
	return c.reply(protocol, call, method, code, out.Bytes())
}

func (c *Conn) call(protocol uint16, method uint32, in *nexstream.Reader, out *nexstream.Writer) (code uint32) {
	handler := c.services[protocol][method]
	if handler == nil {
		logx.Debugf("RMC protocol=%d method=%d is not implemented", protocol, method)
		return CoreNotImplemented
	}
	defer func() {
		if failure := recover(); failure != nil {
			logx.Errorf("RMC handler protocol=%d method=%d panicked: %v\n%s", protocol, method, failure, debug.Stack())
			failures.Add(1)
			code = CoreException
		}
	}()
	params := in.Rest()
	err := handler(c, in, out)
	var refused *Error
	switch {
	case err == nil:
		return 0
	case errors.As(err, &refused):
		return refused.Code
	default:
		logx.Warnf("RMC protocol=%d method=%d from %s: %v params=%x", protocol, method, c.RemoteAddr(), err, params[:min(len(params), maxLoggedParams)])
		failures.Add(1)
		return CoreException
	}
}

func writeProtocol(out *nexstream.Writer, protocol uint16, flag uint8) {
	if protocol < extendedID {
		out.U8(uint8(protocol) | flag)
		return
	}
	out.U8(extendedID | flag)
	out.U16(protocol)
}

func (c *Conn) reply(protocol uint16, call, method, code uint32, body []byte) error {
	inner := nexstream.NewWriter(false)
	writeProtocol(inner, protocol, 0)
	if code == 0 {
		inner.Bool(true)
		inner.U32(call)
		inner.U32(method | responseFlag)
		inner.Write(body)
	} else {
		inner.Bool(false)
		inner.U32(code)
		inner.U32(call)
	}
	return c.send(inner.Bytes())
}

func (c *Conn) send(inner []byte) error {
	out := nexstream.NewWriter(false)
	out.Buffer(inner)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Send(out.Bytes())
}

// Request sends a call to the player without waiting for the answer.
func (c *Conn) Request(protocol uint16, method uint32, write func(out *nexstream.Writer)) error {
	inner := nexstream.NewWriter(false)
	writeProtocol(inner, protocol, requestFlag)
	inner.U32(c.nextCall.Add(1) - 1)
	inner.U32(method)
	body := nexstream.NewWriter(c.structHeader)
	write(body)
	inner.Write(body.Bytes())
	return c.send(inner.Bytes())
}

// Refuse is the error for a refused call.
func Refuse(code uint32) error { return &Error{code} }
