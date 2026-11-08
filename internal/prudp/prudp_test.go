package prudp

import (
	"bytes"
	"crypto/rc4"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

func samplePacket(kind uint8) *Packet {
	return &Packet{SourcePort: 15, SourceType: 10, DestPort: 1, DestType: 10, Type: kind, Flags: FlagReliable | FlagNeedAck,
		SessionID: 3, PacketID: 9, Signature: make([]byte, signatureSize), FragmentID: 2, MinorVersion: 4,
		ConnectionSignature: bytes.Repeat([]byte{7}, signatureSize), UnreliableID: 5, MaxSubstreamID: 0, Payload: []byte("data")}
}

func TestEncodeDecode(t *testing.T) {
	for _, kind := range []uint8{TypeSyn, TypeConnect, TypeData, TypeDisconnect, TypePing} {
		original := samplePacket(kind)
		packets, err := Decode(original.Encode())
		if err != nil || len(packets) != 1 {
			t.Fatalf("type %d: %v, %d", kind, err, len(packets))
		}
		got := packets[0]
		if got.Type != kind || got.Flags != original.Flags || got.PacketID != 9 || got.SessionID != 3 ||
			got.SourcePort != 15 || got.SourceType != 10 || string(got.Payload) != "data" {
			t.Fatalf("type %d: %+v", kind, got)
		}
		if !bytes.Equal(got.Encode(), original.Encode()) {
			t.Fatalf("type %d: not stable", kind)
		}
	}
}

func TestSeveralPacketsInOneDatagram(t *testing.T) {
	data := append(samplePacket(TypeData).Encode(), samplePacket(TypePing).Encode()...)
	packets, err := Decode(data)
	if err != nil || len(packets) != 2 || packets[1].Type != TypePing {
		t.Fatalf("%d packets, %v", len(packets), err)
	}
}

func TestDecodeRefusesBadPackets(t *testing.T) {
	good := samplePacket(TypeData).Encode()
	badMagic := bytes.Clone(good)
	badMagic[0] = 0
	badVersion := bytes.Clone(good)
	badVersion[2] = 0
	withoutOption := append(bytes.Clone(good[:headerSize]), []byte("data")...)
	withoutOption[3] = 0
	for name, data := range map[string][]byte{"short": good[:10], "magic": badMagic, "version": badVersion,
		"truncated": good[:len(good)-1], "no fragment option": withoutOption} {
		if _, err := Decode(data); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSignatureCoversTheContent(t *testing.T) {
	signer := NewSigner("6f599f81")
	packet := samplePacket(TypeData)
	first := signer.Sign(packet, []byte("key"), []byte("signature"))
	packet.PacketID++
	if bytes.Equal(first, signer.Sign(packet, []byte("key"), []byte("signature"))) {
		t.Fatal("the packet id is not signed")
	}
	packet.PacketID--
	packet.Payload = []byte("other")
	if bytes.Equal(first, signer.Sign(packet, []byte("key"), []byte("signature"))) {
		t.Fatal("the payload is not signed")
	}
}

func newCipher() (*rc4.Cipher, error) { return rc4.NewCipher([]byte(defaultRC4Key)) }

// startClient runs a Client on a real socket, with nobody on the other side.
func startClient(t *testing.T) (*Server, *Client) {
	t.Helper()
	server, err := Listen("127.0.0.1", 0, Options{AccessKey: "6f599f81", Handler: func(*Client) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	addr := netip.MustParseAddrPort("127.0.0.1:9")
	connect := &Packet{ConnectionSignature: make([]byte, signatureSize), SessionID: 5}
	return server, newClient(server, clientKey{addr, 15, 10}, connect, &loginResult{})
}

func signedForClient(client *Client, packet *Packet) *Packet {
	packet.SourcePort, packet.SourceType, packet.DestPort, packet.DestType = 15, 10, 1, 10
	packet.SessionID = client.remoteSession
	packet.Signature = client.server.signer.Sign(packet, client.sessionKey, client.server.connectionSignature(client.key.addr))
	return packet
}

func dataPacket(client *Client, id uint16, fragment uint8, clear []byte) *Packet {
	return signedForClient(client, &Packet{Type: TypeData, Flags: FlagReliable | FlagNeedAck, PacketID: id,
		FragmentID: fragment, Payload: clear})
}

func TestOutOfOrderFragmentsAreReassembledInOrder(t *testing.T) {
	_, client := startClient(t)
	// The default key, in the order the sender encrypted: each packet is delivered by id.
	sender, _ := newCipher()
	var packets []*Packet
	for i, chunk := range []struct {
		text     string
		fragment uint8
	}{{"one", 1}, {"two", 2}, {"three", 0}} {
		encrypted := make([]byte, len(chunk.text))
		sender.XORKeyStream(encrypted, []byte(chunk.text))
		packets = append(packets, dataPacket(client, uint16(2+i), chunk.fragment, encrypted))
	}
	for _, index := range []int{2, 0, 0, 1} { // out of order, with a duplicate
		if err := client.handle(packets[index]); err != nil {
			t.Fatal(err)
		}
	}
	message, alive := client.Recv()
	if !alive || string(message) != "onetwothree" {
		t.Fatalf("got %q", message)
	}
}

func TestForgedPacketsAreRefusedAndDoNotKeepTheConnectionAlive(t *testing.T) {
	_, client := startClient(t)
	before := client.lastSeen
	forged := dataPacket(client, 2, 0, []byte("x"))
	forged.Signature = make([]byte, signatureSize)
	time.Sleep(2 * time.Millisecond)
	if err := client.handle(forged); err == nil {
		t.Fatal("a bad signature was accepted")
	}
	if !client.lastSeen.Equal(before) {
		t.Fatal("a forged packet counted as life")
	}
}

func TestPacketBeyondTheWindowIsDropped(t *testing.T) {
	_, client := startClient(t)
	if err := client.handle(dataPacket(client, 2+windowSize, 0, []byte("x"))); err == nil {
		t.Fatal("accepted beyond the window")
	}
	if err := client.handle(dataPacket(client, 2+windowSize-1, 0, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if len(client.window) != 1 {
		t.Fatalf("window holds %d", len(client.window))
	}
}

func TestPacketIDsWrapAround(t *testing.T) {
	_, client := startClient(t)
	client.expected = 0xFFFF
	sender, _ := newCipher()
	for i, id := range []uint16{0xFFFF, 0} {
		encrypted := make([]byte, 1)
		sender.XORKeyStream(encrypted, []byte{byte('a' + i)})
		if err := client.handle(dataPacket(client, id, 0, encrypted)); err != nil {
			t.Fatal(err)
		}
		message, _ := client.Recv()
		if string(message) != string(rune('a'+i)) {
			t.Fatalf("id %d gave %q", id, message)
		}
	}
	if client.expected != 1 {
		t.Fatalf("expected = %d", client.expected)
	}
}

func TestMessageTooLargeClosesTheConnection(t *testing.T) {
	_, client := startClient(t)
	client.fragments = make([]byte, maxMessage)
	if err := client.handle(dataPacket(client, 2, 1, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("still open")
	}
}

func TestQueueOverflowClosesTheConnection(t *testing.T) {
	_, client := startClient(t)
	sender, _ := newCipher()
	for i := 0; i <= queueSize; i++ {
		encrypted := make([]byte, 1)
		sender.XORKeyStream(encrypted, []byte{1})
		if err := client.handle(dataPacket(client, uint16(2+i), 0, encrypted)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("still open")
	}
}

func TestAggregateAcks(t *testing.T) {
	_, client := startClient(t)
	for i := 0; i < 5; i++ {
		if err := client.Send([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// New form: acknowledges everything up to 2, and 4.
	payload := []byte{0, 1, 2, 0, 4, 0}
	if err := client.handle(signedForClient(client, &Packet{Type: TypeData, Flags: FlagMultiAck, SubstreamID: 1, Payload: payload})); err != nil {
		t.Fatal(err)
	}
	if len(client.unacked) != 2 || client.unacked[pendingKey{TypeData, 3}] == nil || client.unacked[pendingKey{TypeData, 5}] == nil {
		t.Fatalf("unacked = %v", client.unacked)
	}
	for name, packet := range map[string]*Packet{
		"odd":   {Type: TypeData, Flags: FlagMultiAck, SubstreamID: 1, Payload: []byte{0, 1, 2}},
		"count": {Type: TypeData, Flags: FlagMultiAck, SubstreamID: 1, Payload: []byte{0, 9, 2, 0}},
		"type":  {Type: TypePing, Flags: FlagMultiAck, SubstreamID: 1, Payload: []byte{0, 0, 2, 0}},
	} {
		if err := client.handle(signedForClient(client, packet)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestLongMessagesAreFragmented(t *testing.T) {
	_, client := startClient(t)
	if err := client.Send(make([]byte, fragmentSize*2+1)); err != nil {
		t.Fatal(err)
	}
	if len(client.unacked) != 3 {
		t.Fatalf("%d packets", len(client.unacked))
	}
	var fragments []uint8
	for id := uint16(1); id <= 3; id++ {
		packets, err := Decode(client.unacked[pendingKey{TypeData, id}].data)
		if err != nil {
			t.Fatal(err)
		}
		fragments = append(fragments, packets[0].FragmentID)
	}
	if !bytes.Equal(fragments, []byte{1, 2, 0}) {
		t.Fatalf("fragments = %v", fragments)
	}
}

func TestSilentClientIsClosed(t *testing.T) {
	server, client := startClient(t)
	server.options.IdleTimeout = time.Second
	client.tick(time.Now().Add(2 * time.Second))
	select {
	case <-client.Done():
	default:
		t.Fatal("still open")
	}
}

func TestLostPacketGivesUpAfterTheResendLimit(t *testing.T) {
	_, client := startClient(t)
	if err := client.Send([]byte("x")); err != nil {
		t.Fatal(err)
	}
	moment := time.Now()
	for i := 0; i < resendLimit; i++ {
		moment = moment.Add(resendTimeout + time.Millisecond)
		client.lastSeen = moment
		client.tick(moment)
	}
	select {
	case <-client.Done():
		t.Fatal("gave up too early")
	default:
	}
	moment = moment.Add(resendTimeout + time.Millisecond)
	client.lastSeen = moment
	client.tick(moment)
	select {
	case <-client.Done():
	default:
		t.Fatal("still open")
	}
}

func TestRandomDatagramsDoNotPanic(t *testing.T) {
	random := rand.New(rand.NewSource(0x5EED2027))
	for i := 0; i < 10000; i++ {
		data := make([]byte, random.Intn(200))
		random.Read(data)
		if len(data) >= 3 && i%2 == 0 { // get past the first check
			data[0], data[1], data[2] = magic[0], magic[1], 1
		}
		_, _ = Decode(data)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(samplePacket(TypeData).Encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		packets, err := Decode(data)
		if err == nil {
			for _, packet := range packets {
				packet.Encode()
			}
		}
	})
}
