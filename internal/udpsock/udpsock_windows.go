//go:build windows

package udpsock

import (
	"net"
	"syscall"
	"unsafe"
)

const sioUDPConnReset = 0x9800000C

// disableConnReset stops Windows from turning the ICMP "port unreachable" of a closed peer into an
// error on the server's socket: under a burst of logins this dropped other players' handshakes.
func disableConnReset(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		var returned, off uint32
		_ = syscall.WSAIoctl(syscall.Handle(fd), sioUDPConnReset, (*byte)(unsafe.Pointer(&off)), 4, nil, 0, &returned, nil, 0)
	})
}
