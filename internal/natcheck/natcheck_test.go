package natcheck

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func start(t *testing.T, sameSocket bool) (*Server, int) {
	t.Helper()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	server := Start([]string{"127.0.0.1", "127.0.0.2"}, []int{port}, sameSocket)
	t.Cleanup(server.Close)
	return server, port
}

func exchange(t *testing.T, conn *net.UDPConn, port int, kind uint32) ([4]uint32, *net.UDPAddr) {
	t.Helper()
	message := make([]byte, messageSize)
	binary.BigEndian.PutUint32(message, kind)
	if _, err := conn.WriteToUDP(message, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64)
	size, sender, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("type %d: %v", kind, err)
	}
	if size != messageSize {
		t.Fatalf("type %d: %d bytes", kind, size)
	}
	var fields [4]uint32
	for i := range fields {
		fields[i] = binary.BigEndian.Uint32(buffer[i*4:])
	}
	return fields, sender
}

func client(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestReplies(t *testing.T) {
	_, port := start(t, false)
	conn := client(t)
	own := uint32(conn.LocalAddr().(*net.UDPAddr).Port)

	fields, sender := exchange(t, conn, port, 1)
	if fields != [4]uint32{1, own, 0x7F000001, 0x7F000001} || sender.Port != port {
		t.Fatalf("type 1: %x from %v", fields, sender)
	}
	fields, sender = exchange(t, conn, port, 3)
	if fields[3] != 0x7F000001 || sender.Port == port || !sender.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("type 3: %x from %v", fields, sender)
	}
	fields, sender = exchange(t, conn, port, 2)
	if fields[3] != 0x7F000002 || !sender.IP.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("type 2: %x from %v", fields, sender)
	}
}

func TestSameSocketAnswersEverythingFromTheReceiver(t *testing.T) {
	_, port := start(t, true)
	conn := client(t)
	for _, kind := range []uint32{2, 3, 102} {
		if _, sender := exchange(t, conn, port, kind); sender.Port != port {
			t.Fatalf("type %d from %v", kind, sender)
		}
	}
}

func TestShortAndUnknownMessagesGetNoReply(t *testing.T) {
	server, port := start(t, false)
	conn := client(t)
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	_, _ = conn.WriteToUDP([]byte{0, 0, 0, 1}, target)
	unknown := make([]byte, messageSize)
	binary.BigEndian.PutUint32(unknown, 999)
	_, _ = conn.WriteToUDP(unknown, target)
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := conn.ReadFromUDP(make([]byte, 64)); err == nil {
		t.Fatal("got a reply")
	}
	if _, found := server.Consume("127.0.0.1"); found {
		t.Fatal("only a real NAT check registers an endpoint")
	}
}

func TestRateLimit(t *testing.T) {
	_, port := start(t, false)
	conn := client(t)
	message := make([]byte, messageSize)
	binary.BigEndian.PutUint32(message, 1)
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	for i := 0; i < rateLimit; i++ {
		exchange(t, conn, port, 1)
	}
	_, _ = conn.WriteToUDP(message, target)
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := conn.ReadFromUDP(make([]byte, 64)); err == nil {
		t.Fatal("not rate limited")
	}
}

func TestObservationsAreConsumedOnceAndExpire(t *testing.T) {
	server := &Server{observations: map[string][]observation{}}
	server.observe("1.1.1.1", 10)
	server.observe("1.1.1.1", 20)
	server.observe("2.2.2.2", 30)
	if port, found := server.Consume("1.1.1.1"); !found || port != 20 {
		t.Fatalf("got %d, %t", port, found)
	}
	if port, found := server.Consume("1.1.1.1"); !found || port != 10 {
		t.Fatalf("got %d, %t", port, found)
	}
	if _, found := server.Consume("1.1.1.1"); found {
		t.Fatal("consumed twice")
	}
	if port, _ := server.Consume("2.2.2.2"); port != 30 {
		t.Fatalf("another host's observation: %d", port)
	}
	server.observations["3.3.3.3"] = []observation{{5, time.Now().Add(-observationMaxAge - time.Second)}}
	if _, found := server.Consume("3.3.3.3"); found {
		t.Fatal("a stale observation was used")
	}
	for i := 0; i < maxObservations+4; i++ {
		server.observe("4.4.4.4", i)
	}
	if count := len(server.observations["4.4.4.4"]); count != maxObservations {
		t.Fatalf("%d observations kept", count)
	}
}
