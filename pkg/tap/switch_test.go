package tap

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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

	badCsum := uint16(tcp[16])<<8 | uint16(tcp[17])

	fixL4Checksum(frame)

	newCsum := uint16(tcp[16])<<8 | uint16(tcp[17])

	if newCsum == badCsum {
		t.Errorf("checksum was not recomputed: still 0x%04x", newCsum)
	}
	if newCsum == 0 {
		t.Error("checksum should not be zero after recomputation")
	}

	// The real test: use gvisor's own IsChecksumValid to verify correctness.
	// This is the same validation the destination VM's kernel performs.
	srcAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	dstAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 3})
	tcpHdr := header.TCP(tcp)
	if !tcpHdr.IsChecksumValid(srcAddr, dstAddr, 0, 0) {
		t.Errorf("checksum 0x%04x is not valid per IsChecksumValid (RFC verification)", newCsum)
	}
}

func TestFixL4Checksum_TCP_BadDataOffset(t *testing.T) {
	// A malformed packet with DataOffset > buffer length must not panic.
	frame := make([]byte, 54)
	frame[12] = 0x08 // IPv4
	frame[13] = 0x00
	ip := frame[14:]
	ip[0] = 0x45       // IHL=5
	ip[2] = 0x00       // total length = 40
	ip[3] = 0x28
	ip[9] = 0x06       // TCP
	copy(ip[12:16], []byte{10, 0, 0, 2})
	copy(ip[16:20], []byte{10, 0, 0, 3})

	tcp := frame[34:]
	tcp[12] = 0xf0 // data offset = 15 → 60 bytes (but only 20 bytes of L4 data)
	tcp[13] = 0x02

	original := make([]byte, len(frame))
	copy(original, frame)

	fixL4Checksum(frame) // must not panic

	// Frame should be unchanged (function bailed out)
	for i := range frame {
		if frame[i] != original[i] {
			t.Fatalf("malformed frame was modified at byte %d", i)
		}
	}
}

func TestFixL4Checksum_IPFragment(t *testing.T) {
	// Non-first IP fragments have no transport header — must not be touched.
	frame := make([]byte, 54)
	frame[12] = 0x08 // IPv4
	frame[13] = 0x00
	ip := frame[14:]
	ip[0] = 0x45       // IHL=5
	ip[2] = 0x00       // total length = 40
	ip[3] = 0x28
	ip[6] = 0x00       // flags + fragment offset (high bits)
	ip[7] = 0x10       // fragment offset = 16 (non-zero → not first fragment)
	ip[9] = 0x06       // TCP
	copy(ip[12:16], []byte{10, 0, 0, 2})
	copy(ip[16:20], []byte{10, 0, 0, 3})

	original := make([]byte, len(frame))
	copy(original, frame)

	fixL4Checksum(frame) // should skip — no transport header

	for i := range frame {
		if frame[i] != original[i] {
			t.Fatalf("IP fragment was modified at byte %d", i)
		}
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

func TestDebugParser_RuntIPv4_NoPanic(t *testing.T) {
	// A short IPv4 frame (< 20 bytes of IP) must not panic the debug TCP parser.
	// ipBuf[9] (protocol field) would be out of bounds without proper guard.

	sw := NewSwitch(true) // debug = true
	sw.gateway = &mockGateway{mac: tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")}

	conn := &mockConn{}
	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: conn, protocolImpl: bessProto}

	// Ethernet(14) + 5 bytes of IPv4 (version nibble = 4, but way too short)
	frame := make([]byte, header.EthernetMinimumSize+5)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}) // dst != gateway
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}) // src
	frame[12] = 0x08                                                // EtherType: IPv4
	frame[13] = 0x00
	frame[14] = 0x45 // version=4, IHL=5

	// Must not panic
	sw.rxBuf(nil, 0, frame)
}

func TestDebugParser_BadIHL_NoPanic(t *testing.T) {
	// IHL=1 (ihl=4) is invalid — the debug parser must not index into
	// IP header bytes as if they were TCP fields.

	sw := NewSwitch(true) // debug = true
	sw.gateway = &mockGateway{mac: tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")}

	conn := &mockConn{}
	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: conn, protocolImpl: bessProto}

	// Ethernet(14) + 34 bytes of "IPv4" — enough for ihl(4)+17=21 check to pass
	frame := make([]byte, header.EthernetMinimumSize+34)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}) // dst != gateway
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}) // src
	frame[12] = 0x08                                                // EtherType: IPv4
	frame[13] = 0x00
	frame[14] = 0x41 // version=4, IHL=1 (invalid — less than 5)
	frame[23] = 0x06 // byte 9 of IP = protocol TCP (but ihl=4 means this is wrong offset)

	// Must not panic, and ideally should not log garbage
	sw.rxBuf(nil, 0, frame)
}

func TestFixL4Checksum_FirstFragment(t *testing.T) {
	// First IP fragment (offset=0, MF=1) has partial payload —
	// checksum recomputation would produce garbage. Must be skipped.

	frame := make([]byte, 54)
	frame[12] = 0x08 // IPv4
	frame[13] = 0x00
	ip := frame[14:]
	ip[0] = 0x45       // IHL=5
	ip[2] = 0x00       // total length = 40
	ip[3] = 0x28
	ip[6] = 0x20       // flags: MF=1, fragment offset = 0 (high byte: 0010 0000)
	ip[7] = 0x00       // fragment offset low byte = 0
	ip[9] = 0x06       // TCP
	copy(ip[12:16], []byte{10, 0, 0, 2})
	copy(ip[16:20], []byte{10, 0, 0, 3})

	tcp := frame[34:]
	tcp[12] = 0x50 // data offset = 5
	tcp[13] = 0x02 // SYN
	tcp[16] = 0xAB // checksum high
	tcp[17] = 0xCD // checksum low

	original := make([]byte, len(frame))
	copy(original, frame)

	fixL4Checksum(frame) // should skip — first fragment

	for i := range frame {
		if frame[i] != original[i] {
			t.Fatalf("first fragment was modified at byte %d: want 0x%02x, got 0x%02x",
				i, original[i], frame[i])
		}
	}
}

// enobufsConn returns ENOBUFS for the first N writes, then succeeds.
// If failForever is true, it always returns ENOBUFS.
type enobufsConn struct {
	net.Conn
	failCount   int
	failForever bool
	writes      int
}

func (c *enobufsConn) Write(b []byte) (int, error) {
	c.writes++
	if c.failForever || c.writes <= c.failCount {
		return 0, syscall.ENOBUFS
	}
	return len(b), nil
}
func (c *enobufsConn) Close() error { return nil }
func (c *enobufsConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (c *enobufsConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func TestTxBuf_ENOBUFS_BoundedRetry(t *testing.T) {
	t.Run("transient_clears", func(t *testing.T) {
		// ENOBUFS for 3 writes then succeeds — should deliver
		sw := NewSwitch(false)
		conn := &enobufsConn{failCount: 3}
		bessProto := &bessProtocol{}
		pc := protocolConn{Conn: conn, protocolImpl: bessProto}
		sw.connLock.Lock()
		sw.conns[0] = pc
		sw.connLock.Unlock()

		err := sw.txBuf(0, pc, []byte("hello"))
		if err != nil {
			t.Fatalf("expected successful write after transient ENOBUFS, got: %v", err)
		}
		// Should have attempted 4 writes total (3 fail + 1 success)
		if conn.writes != 4 {
			t.Errorf("expected 4 write attempts, got %d", conn.writes)
		}
	})

	t.Run("exhausted_retries", func(t *testing.T) {
		// ENOBUFS forever — must NOT hang, should return error
		sw := NewSwitch(false)
		conn := &enobufsConn{failForever: true}
		bessProto := &bessProtocol{}
		pc := protocolConn{Conn: conn, protocolImpl: bessProto}
		sw.connLock.Lock()
		sw.conns[0] = pc
		sw.connLock.Unlock()

		done := make(chan error, 1)
		go func() {
			done <- sw.txBuf(0, pc, []byte("hello"))
		}()

		select {
		case err := <-done:
			if err == nil {
				t.Fatal("expected error after exhausted retries, got nil")
			}
			if !errors.Is(err, syscall.ENOBUFS) {
				t.Fatalf("expected ENOBUFS error, got: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("txBuf hung on persistent ENOBUFS — bounded retry not working")
		}

		// Connection should have been disconnected
		sw.connLock.Lock()
		_, exists := sw.conns[0]
		sw.connLock.Unlock()
		if exists {
			t.Error("conn 0 should have been removed after exhausted ENOBUFS retries")
		}
	})
}

func TestRxBuf_SkipsCAMUpdate_AfterDisconnect(t *testing.T) {
	// If a connection has been disconnected (removed from conns),
	// rxBuf must NOT re-insert a CAM entry pointing to the dead conn ID.

	sw := NewSwitch(false)
	sw.gateway = &mockGateway{mac: tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")}

	bessProto := &bessProtocol{}
	sw.conns[0] = protocolConn{Conn: &mockConn{}, protocolImpl: bessProto}

	srcMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")

	// Simulate disconnect: remove conn 0 and its CAM entry
	delete(sw.conns, 0)
	delete(sw.cam, srcMAC)

	// Build frame from srcMAC on conn 0 (now dead)
	frame := make([]byte, header.EthernetMinimumSize)
	copy(frame[0:6], []byte(sw.gateway.LinkAddress())) // dst = gateway (avoids tx path)
	copy(frame[6:12], []byte(srcMAC))
	frame[12] = 0x08
	frame[13] = 0x00

	sw.rxBuf(nil, 0, frame)

	// CAM should NOT have re-learned srcMAC → 0
	sw.camLock.RLock()
	_, exists := sw.cam[srcMAC]
	sw.camLock.RUnlock()
	if exists {
		t.Error("CAM should not have re-inserted entry for disconnected conn 0")
	}
}

func TestFixL4Checksum_TCP_WithPadding(t *testing.T) {
	// A 60-byte Ethernet frame (minimum) carrying a 40-byte IP packet
	// has 6 bytes of trailing padding. The checksum must be computed
	// over only the IP payload, not the padding.

	// Build: Ethernet(14) + IPv4(20) + TCP(20) + Padding(6) = 60 bytes
	frame := make([]byte, 60)

	// Ethernet header
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 0x03})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 0x02})
	frame[12] = 0x08
	frame[13] = 0x00

	// IPv4 header (20 bytes) — TotalLength = 40 (NOT 46)
	ip := frame[14:]
	ip[0] = 0x45       // version=4, IHL=5
	ip[1] = 0x00       // DSCP/ECN
	ip[2] = 0x00       // total length = 40
	ip[3] = 0x28
	ip[8] = 0x40       // TTL
	ip[9] = 0x06       // TCP
	copy(ip[12:16], []byte{10, 0, 0, 2})
	copy(ip[16:20], []byte{10, 0, 0, 3})

	// TCP header (20 bytes) — SYN with bogus partial checksum
	tcp := frame[34:]
	tcp[0] = 0xa3 // src port 41888
	tcp[1] = 0xc0
	tcp[2] = 0x1f // dst port 8080
	tcp[3] = 0x90
	tcp[12] = 0x50 // data offset = 5
	tcp[13] = 0x02 // SYN
	tcp[14] = 0xff // window
	tcp[15] = 0xff
	tcp[16] = 0x14 // bogus checksum
	tcp[17] = 0x33

	// Padding bytes (54..59) — non-zero to trigger the bug
	frame[54] = 0xDE
	frame[55] = 0xAD
	frame[56] = 0xBE
	frame[57] = 0xEF
	frame[58] = 0xCA
	frame[59] = 0xFE

	fixL4Checksum(frame)

	// Verify with gvisor's own IsChecksumValid
	srcAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	dstAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 3})
	tcpHdr := header.TCP(tcp[:20]) // only the real TCP header, no padding
	if !tcpHdr.IsChecksumValid(srcAddr, dstAddr, 0, 0) {
		csum := uint16(tcp[16])<<8 | uint16(tcp[17])
		t.Errorf("checksum 0x%04x invalid — padding bytes likely included in computation", csum)
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
