//go:build !windows

package udpsock

import "net"

func disableConnReset(*net.UDPConn) {}
