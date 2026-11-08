// Package udpsock opens the server's UDP sockets.
package udpsock

import (
	"net"
	"net/netip"
)

// Listen binds an IPv4 UDP socket; a wildcard host binds every interface, port 0 picks a free port.
func Listen(host string, port int) (*net.UDPConn, error) {
	address := netip.IPv4Unspecified()
	if host != "" && host != "0.0.0.0" && host != "::" {
		parsed, err := netip.ParseAddr(host)
		if err != nil {
			return nil, err
		}
		address = parsed
	}
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, uint16(port))))
	if err != nil {
		return nil, err
	}
	disableConnReset(conn)
	return conn, nil
}
