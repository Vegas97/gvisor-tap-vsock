package tap

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// mockGateway implements VirtualDevice for testing.
type mockGateway struct {
	mac tcpip.LinkAddress
}

func (m *mockGateway) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {}
func (m *mockGateway) LinkAddress() tcpip.LinkAddress                                            { return m.mac }
func (m *mockGateway) IP() string                                                                { return "10.0.0.1" }

// mockConn implements net.Conn with a controllable Write.
type mockConn struct {
	net.Conn // embed for unimplemented methods
	written  [][]byte
	writeErr error
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	m.written = append(m.written, cp)
	return len(b), nil
}

func (m *mockConn) Close() error { return nil }

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// makeBroadcastFrame builds a minimal Ethernet frame with broadcast destination.
func makeBroadcastFrame(srcMAC net.HardwareAddr) []byte {
	frame := make([]byte, header.EthernetMinimumSize)
	// Destination: broadcast (ff:ff:ff:ff:ff:ff)
	copy(frame[0:6], header.EthernetBroadcastAddress)
	// Source
	copy(frame[6:12], srcMAC)
	// EtherType: IPv4
	frame[12] = 0x08
	frame[13] = 0x00
	return frame
}

func TestBroadcast_ContinuesAfterOneConnFails(t *testing.T) {
	// Given 3 connections where conn #1 has a broken writer
	// When a broadcast packet is sent
	// Then conn #0 and #2 should still receive the frame

	sw := NewSwitch(false)

	conn0 := &mockConn{}
	conn1 := &mockConn{writeErr: errors.New("broken pipe")}
	conn2 := &mockConn{}

	// Register 3 connections using bess protocol (non-stream, simplest)
	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: conn0, protocolImpl: bessProto}
	sw.conns[1] = protocolConn{Conn: conn1, protocolImpl: bessProto}
	sw.conns[2] = protocolConn{Conn: conn2, protocolImpl: bessProto}

	// Source MAC doesn't match any conn (so no conn is skipped as source)
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}
	frame := makeBroadcastFrame(srcMAC)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()

	err := sw.txPkt(pkt)
	if err != nil {
		t.Fatalf("txPkt returned error: %v (broadcast should not abort on single conn failure)", err)
	}

	// conn0 should have received the frame
	if len(conn0.written) != 1 {
		t.Errorf("conn0: expected 1 write, got %d", len(conn0.written))
	}

	// conn1 failed — that's expected, it should have been disconnected
	if _, exists := sw.conns[1]; exists {
		t.Error("conn1 should have been removed from conns after write failure")
	}

	// conn2 should have received the frame despite conn1's failure
	if len(conn2.written) != 1 {
		t.Errorf("conn2: expected 1 write, got %d — broadcast aborted after conn1 failure", len(conn2.written))
	}

	// Sent counter should reflect 2 successful deliveries
	expectedSent := uint64(len(frame) * 2)
	if atomic.LoadUint64(&sw.Sent) != expectedSent {
		t.Errorf("Sent: expected %d, got %d", expectedSent, atomic.LoadUint64(&sw.Sent))
	}
}

func TestBroadcast_SkipsSourceConn(t *testing.T) {
	// The source connection should NOT receive its own broadcast

	sw := NewSwitch(false)

	conn0 := &mockConn{}
	conn1 := &mockConn{}

	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: conn0, protocolImpl: bessProto}
	sw.conns[1] = protocolConn{Conn: conn1, protocolImpl: bessProto}

	// Source MAC maps to conn0 via CAM table
	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	sw.cam["\x02\x00\x00\x00\x00\x01"] = 0

	frame := makeBroadcastFrame(srcMAC)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()

	err := sw.txPkt(pkt)
	if err != nil {
		t.Fatalf("txPkt returned error: %v", err)
	}

	// conn0 is the source — should NOT receive the broadcast
	if len(conn0.written) != 0 {
		t.Errorf("conn0 (source): expected 0 writes, got %d", len(conn0.written))
	}

	// conn1 should receive it
	if len(conn1.written) != 1 {
		t.Errorf("conn1: expected 1 write, got %d", len(conn1.written))
	}
}

func TestRxBuf_MACMigration_UpdatesCAM(t *testing.T) {
	// When a VM is destroyed and recreated with the same MAC,
	// rxBuf should update the CAM to point to the new connection.
	// The old connection is NOT proactively killed (that would enable
	// MAC-spoofing attacks); it cleans up via its own goroutine lifecycle.

	sw := NewSwitch(false)
	sw.gateway = &mockGateway{mac: tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")}

	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: &mockConn{}, protocolImpl: bessProto}
	sw.conns[1] = protocolConn{Conn: &mockConn{}, protocolImpl: bessProto}
	sw.nextConnID = 2

	mac := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	sw.cam[mac] = 0 // first-boot CAM entry

	// Packet arrives from the new connection (conn 1) with the same MAC
	frame := make([]byte, header.EthernetMinimumSize)
	copy(frame[0:6], header.EthernetBroadcastAddress)
	copy(frame[6:12], []byte(mac))
	frame[12] = 0x08
	frame[13] = 0x00

	sw.rxBuf(nil, 1, frame)

	// CAM should now point to the new connection
	sw.camLock.RLock()
	camID, ok := sw.cam[mac]
	sw.camLock.RUnlock()
	if !ok {
		t.Fatal("CAM entry for MAC should exist")
	}
	if camID != 1 {
		t.Errorf("CAM should point to new conn 1, got %d", camID)
	}

	// Old connection should still exist (cleaned up by its own goroutine)
	sw.connLock.Lock()
	_, oldExists := sw.conns[0]
	sw.connLock.Unlock()
	if !oldExists {
		t.Error("old conn 0 should still exist (not proactively killed)")
	}
}

func TestDisconnect_Idempotent(t *testing.T) {
	// disconnect() should be safe to call twice for the same connection.
	// This happens when txBuf error cleanup races with Accept's deferred disconnect.

	sw := NewSwitch(false)

	conn := &mockConn{}
	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: conn, protocolImpl: bessProto}
	sw.cam[tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")] = 0

	// First disconnect — should clean up
	sw.disconnect(0, conn)

	if _, ok := sw.conns[0]; ok {
		t.Error("conn 0 should be removed after first disconnect")
	}

	// Second disconnect — should be a no-op, not panic or double-close
	sw.disconnect(0, conn) // must not panic
}

func TestFixL4Checksum_TCP(t *testing.T) {
	// Simulate a TCP SYN with a partial (pseudo-header only) checksum,
	// as produced by a VM kernel with checksum offloading.

	// Build: Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes
	frame := make([]byte, 54)

	// Ethernet header
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 0x03}) // dst MAC
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 0x02}) // src MAC
	frame[12] = 0x08                                    // EtherType: IPv4
	frame[13] = 0x00

	// IPv4 header (20 bytes)
	ip := frame[14:]
	ip[0] = 0x45       // version=4, IHL=5 (20 bytes)
	ip[1] = 0x00       // DSCP/ECN
	ip[2] = 0x00       // total length = 40
	ip[3] = 0x28       //
	ip[8] = 0x40       // TTL
	ip[9] = 0x06       // protocol = TCP
	copy(ip[12:16], []byte{10, 0, 0, 2}) // src IP
	copy(ip[16:20], []byte{10, 0, 0, 3}) // dst IP

	// TCP header (20 bytes) — SYN with WRONG checksum (partial/offloaded)
	tcp := frame[34:]
	tcp[0] = 0xa3 // src port 41888 (high byte)
	tcp[1] = 0xc0 // src port 41888 (low byte)
	tcp[2] = 0x1f // dst port 8080
	tcp[3] = 0x90
	tcp[12] = 0x50 // data offset = 5 (20 bytes)
	tcp[13] = 0x02 // flags = SYN
	tcp[14] = 0xff // window size
	tcp[15] = 0xff
	tcp[16] = 0x14 // bogus partial checksum = 0x1433
	tcp[17] = 0x33

	// Save the bad checksum for comparison
	badCsum := uint16(tcp[16])<<8 | uint16(tcp[17])

	fixL4Checksum(frame)

	newCsum := uint16(tcp[16])<<8 | uint16(tcp[17])

	if newCsum == badCsum {
		t.Errorf("checksum was not recomputed: still 0x%04x", newCsum)
	}
	if newCsum == 0 {
		t.Error("checksum should not be zero after recomputation")
	}

	// Verify the checksum is actually correct by recomputing independently
	tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	srcAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	dstAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 3})
	tcpHdr := header.TCP(tcp)
	tcpHdr.SetChecksum(0)
	psum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, 20)
	expected := tcpHdr.CalculateChecksum(psum)
	if newCsum != expected {
		t.Errorf("checksum mismatch: got 0x%04x, expected 0x%04x", newCsum, expected)
	}
}

func TestFixL4Checksum_NonTCP(t *testing.T) {
	// ARP frame should pass through unchanged
	frame := make([]byte, 42)
	copy(frame[0:6], header.EthernetBroadcastAddress)
	frame[12] = 0x08 // EtherType: ARP
	frame[13] = 0x06

	original := make([]byte, len(frame))
	copy(original, frame)

	fixL4Checksum(frame)

	for i := range frame {
		if frame[i] != original[i] {
			t.Fatalf("ARP frame was modified at byte %d", i)
		}
	}
}

func TestUnicast_StillReturnsErrorOnFailure(t *testing.T) {
	// Unicast behavior should NOT change — errors should still propagate

	sw := NewSwitch(false)

	conn0 := &mockConn{writeErr: errors.New("broken pipe")}

	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: conn0, protocolImpl: bessProto}

	// Set up CAM entry for unicast destination
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	sw.cam["\x02\x00\x00\x00\x00\x01"] = 0

	// Build unicast frame (not broadcast)
	frame := make([]byte, header.EthernetMinimumSize)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x99})
	frame[12] = 0x08
	frame[13] = 0x00

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()

	err := sw.txPkt(pkt)
	if err == nil {
		t.Fatal("unicast to broken conn should return error, got nil")
	}
}
