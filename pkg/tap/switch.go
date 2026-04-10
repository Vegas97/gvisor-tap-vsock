package tap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/containers/gvisor-tap-vsock/pkg/notification"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type VirtualDevice interface {
	DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
	LinkAddress() tcpip.LinkAddress
	IP() string
}

type NetworkSwitch interface {
	DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
}

type Switch struct {
	Sent     uint64
	Received uint64

	debug bool

	nextConnID int
	conns      map[int]protocolConn
	connLock   sync.Mutex

	cam     map[tcpip.LinkAddress]int
	camLock sync.RWMutex

	writeLock sync.Mutex

	gateway VirtualDevice

	notificationSender *notification.NotificationSender
}

func NewSwitch(debug bool) *Switch {
	return &Switch{
		debug: debug,
		conns: make(map[int]protocolConn),
		cam:   make(map[tcpip.LinkAddress]int),
	}
}

func (e *Switch) CAM() map[string]int {
	e.camLock.RLock()
	defer e.camLock.RUnlock()
	ret := make(map[string]int)
	for address, port := range e.cam {
		ret[address.String()] = port
	}
	return ret
}

func (e *Switch) Connect(ep VirtualDevice) {
	e.gateway = ep
}

func (e *Switch) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if err := e.tx(pkt); err != nil {
		log.Error(err)
	}
}

func (e *Switch) Accept(ctx context.Context, rawConn net.Conn, protocol types.Protocol) error {
	conn := protocolConn{Conn: rawConn, protocolImpl: protocolImplementation(protocol)}
	log.Debugf("new connection from %s to %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	id, failed := e.connect(conn)
	if failed {
		log.Error("connection failed")
		return conn.Close()

	}

	defer func() {
		e.connLock.Lock()
		defer e.connLock.Unlock()
		e.disconnect(id, conn)
	}()
	if err := e.rx(ctx, id, conn); err != nil {
		err := fmt.Errorf("cannot receive packets from %s, disconnecting: %w", conn.RemoteAddr().String(), err)
		log.Error(err)
		return err
	}
	return nil
}

func (e *Switch) connect(conn protocolConn) (int, bool) {
	e.connLock.Lock()
	defer e.connLock.Unlock()

	id := e.nextConnID
	e.nextConnID++

	e.conns[id] = conn
	return id, false
}

func (e *Switch) tx(pkt *stack.PacketBuffer) error {
	return e.txPkt(pkt)
}

func (e *Switch) txPkt(pkt *stack.PacketBuffer) error {
	e.writeLock.Lock()
	defer e.writeLock.Unlock()

	e.connLock.Lock()
	defer e.connLock.Unlock()

	buf := pkt.ToView().AsSlice()
	eth := header.Ethernet(buf)
	dst := eth.DestinationAddress()
	src := eth.SourceAddress()

	size := pkt.Size()
	if size < 0 {
		return fmt.Errorf("packet size out of range")
	}
	if dst == header.EthernetBroadcastAddress {
		e.camLock.RLock()
		srcID, ok := e.cam[src]
		if !ok {
			srcID = -1
		}
		e.camLock.RUnlock()
		log.Debugf("txPkt: broadcast from %s (connID=%d), flooding to %d conns", src, srcID, len(e.conns))
		for id, conn := range e.conns {
			if id == srcID {
				continue
			}

			if err := e.txBuf(id, conn, buf); err != nil {
				log.Errorf("broadcast write to conn %d failed: %s", id, err)
				continue
			}

			atomic.AddUint64(&e.Sent, uint64(size))
		}
	} else {
		e.camLock.RLock()
		id, ok := e.cam[dst]
		if !ok {
			e.camLock.RUnlock()
			log.Debugf("txPkt: unicast dst=%s NOT in CAM, dropping frame", dst)
			return nil
		}
		e.camLock.RUnlock()
		log.Debugf("txPkt: unicast dst=%s → conn %d", dst, id)
		conn := e.conns[id]
		err := e.txBuf(id, conn, buf)
		if err != nil {
			return err
		}
		atomic.AddUint64(&e.Sent, uint64(size))
	}
	return nil
}

func (e *Switch) txBuf(id int, conn protocolConn, buf []byte) error {
	if conn.protocolImpl.Stream() {
		size := conn.protocolImpl.(streamProtocol).Buf()
		conn.protocolImpl.(streamProtocol).Write(size, len(buf))
		buf = append(size, buf...)
	}
	for {
		if _, err := conn.Write(buf); err != nil {
			if errors.Is(err, syscall.ENOBUFS) {
				// socket buffer can be full keep retrying sending the same data
				// again until it works or we get a different error
				// https://github.com/containers/gvisor-tap-vsock/issues/367
				continue
			}
			e.disconnect(id, conn)
			return err
		}
		return nil
	}
}

func (e *Switch) disconnect(id int, conn net.Conn) {
	// Guard: if the connection was already removed (e.g. by txBuf error
	// cleanup racing with Accept's deferred disconnect), skip the
	// double-close.
	if _, ok := e.conns[id]; !ok {
		return
	}

	e.camLock.Lock()
	defer e.camLock.Unlock()

	for address, targetConn := range e.cam {
		if targetConn == id {
			if e.notificationSender != nil {
				e.notificationSender.Send(types.NotificationMessage{
					NotificationType: types.ConnectionClosed,
					MacAddress:       address.String(),
				})
			}
			delete(e.cam, address)
		}
	}
	_ = conn.Close()
	delete(e.conns, id)
}

func (e *Switch) rx(ctx context.Context, id int, conn protocolConn) error {
	if conn.protocolImpl.Stream() {
		return e.rxStream(ctx, id, conn, conn.protocolImpl.(streamProtocol))
	}
	return e.rxNonStream(ctx, id, conn)
}

func (e *Switch) rxNonStream(ctx context.Context, id int, conn net.Conn) error {
	bufSize := 1024 * 128
	buf := make([]byte, bufSize)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
			// passthrough
		}
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("cannot read size from socket: %w", err)
		}
		e.rxBuf(ctx, id, buf[:n])
	}
	return nil
}

func (e *Switch) rxStream(ctx context.Context, id int, conn net.Conn, sProtocol streamProtocol) error {
	reader := bufio.NewReader(conn)
	sizeBuf := sProtocol.Buf()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
			// passthrough
		}
		_, err := io.ReadFull(reader, sizeBuf)
		if err != nil {
			return fmt.Errorf("cannot read size from socket: %w", err)
		}
		size := sProtocol.Read(sizeBuf)
		if size < header.EthernetMinimumSize || size > 64*1024 {
			return fmt.Errorf("invalid frame size %d from conn %d (expected %d–%d)",
				size, id, header.EthernetMinimumSize, 64*1024)
		}

		buf := make([]byte, size)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return fmt.Errorf("cannot read packet from socket: %w", err)
		}
		e.rxBuf(ctx, id, buf)
	}
	return nil
}

func (e *Switch) rxBuf(_ context.Context, id int, buf []byte) {
	if len(buf) < header.EthernetMinimumSize {
		log.Debugf("dropping runt frame (%d bytes) from conn %d", len(buf), id)
		return
	}

	if e.debug {
		packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
		log.Info(packet.String())
	}

	eth := header.Ethernet(buf)

	e.camLock.Lock()
	oldID, exists := e.cam[eth.SourceAddress()]
	e.cam[eth.SourceAddress()] = id
	e.camLock.Unlock()

	if !exists {
		log.Infof("CAM learned: %s → conn %d", eth.SourceAddress(), id)
	} else if oldID != id {
		log.Infof("MAC %s migrated from conn %d to conn %d",
			eth.SourceAddress(), oldID, id)
	}

	if (!exists || (exists && oldID != id)) && e.notificationSender != nil {
		e.notificationSender.Send(types.NotificationMessage{
			NotificationType: types.ConnectionEstablished,
			MacAddress:       eth.SourceAddress().String(),
		})
	}

	dst := eth.DestinationAddress()
	gwMAC := e.gateway.LinkAddress()
	if dst != gwMAC {
		// Log L2 frame details including TCP checksum for diagnostics
		if e.debug && len(buf) > header.EthernetMinimumSize {
			ipBuf := buf[header.EthernetMinimumSize:]
			if len(ipBuf) > 0 && (ipBuf[0]>>4) == 4 { // IPv4
				ihl := int(ipBuf[0]&0x0f) * 4
				proto := ipBuf[9]
				if proto == 6 && len(ipBuf) > ihl+17 { // TCP
					tcpBuf := ipBuf[ihl:]
					csum := uint16(tcpBuf[16])<<8 | uint16(tcpBuf[17])
					srcPort := uint16(tcpBuf[0])<<8 | uint16(tcpBuf[1])
					dstPort := uint16(tcpBuf[2])<<8 | uint16(tcpBuf[3])
					flags := tcpBuf[13]
					log.Debugf("L2 switch: TCP %s:%d → %s:%d flags=0x%02x csum=0x%04x len=%d",
						eth.SourceAddress(), srcPort, dst, dstPort, flags, csum, len(buf))
				}
			}
		}
		log.Debugf("L2 switch: src=%s dst=%s (gateway=%s) → forwarding via CAM",
			eth.SourceAddress(), dst, gwMAC)
		fixL4Checksum(buf)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf),
		})
		if err := e.tx(pkt); err != nil {
			log.Errorf("L2 switch: tx error: %s", err)
		}
		pkt.DecRef()
	} else {
		log.Debugf("L2 switch: src=%s dst=%s → gateway (dst matches gateway MAC)",
			eth.SourceAddress(), dst)
	}
	if dst == gwMAC || dst == header.EthernetBroadcastAddress {
		data := buffer.MakeWithData(buf)
		data.TrimFront(header.EthernetMinimumSize)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: data,
		})
		e.gateway.DeliverNetworkPacket(eth.Type(), pkt)
		pkt.DecRef()
	}

	atomic.AddUint64(&e.Received, uint64(len(buf)))
}

func protocolImplementation(protocol types.Protocol) protocol {
	switch protocol {
	case types.QemuProtocol:
		return &qemuProtocol{}
	case types.BessProtocol:
		return &bessProtocol{}
	case types.VfkitProtocol:
		return &vfkitProtocol{}
	default:
		return &hyperkitProtocol{}
	}
}

func (e *Switch) SetNotificationSender(notificationSender *notification.NotificationSender) {
	e.notificationSender = notificationSender
}

// fixL4Checksum recomputes TCP/UDP checksums on L2-switched frames.
// VM kernels with checksum offloading write only a partial checksum
// (pseudo-header) and expect the NIC to finish it. In the L2 switch
// path there is no NIC, so we must compute the full checksum before
// forwarding to the destination VM.
func fixL4Checksum(buf []byte) {
	if len(buf) < header.EthernetMinimumSize+header.IPv4MinimumSize {
		return
	}

	ethType := header.Ethernet(buf).Type()
	if ethType != header.IPv4ProtocolNumber {
		return // only handle IPv4 for now
	}

	ipBuf := buf[header.EthernetMinimumSize:]
	ip := header.IPv4(ipBuf)
	if !ip.IsValid(len(ipBuf)) {
		return
	}

	hdrLen := int(ip.HeaderLength())
	if hdrLen < header.IPv4MinimumSize || len(ipBuf) < hdrLen {
		return
	}

	// Skip non-first IP fragments — they have no transport header.
	if ip.FragmentOffset() != 0 {
		return
	}

	l4Buf := ipBuf[hdrLen:]
	l4Len := uint16(len(l4Buf))
	srcAddr := ip.SourceAddress()
	dstAddr := ip.DestinationAddress()

	switch ip.TransportProtocol() {
	case header.TCPProtocolNumber:
		if len(l4Buf) < header.TCPMinimumSize {
			return
		}
		tcp := header.TCP(l4Buf)
		dataOffset := int(tcp.DataOffset())
		if dataOffset < header.TCPMinimumSize || dataOffset > len(l4Buf) {
			return
		}
		tcp.SetChecksum(0)
		payload := l4Buf[dataOffset:]
		psum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, l4Len)
		psum = checksum.Checksum(payload, psum)
		tcp.SetChecksum(^tcp.CalculateChecksum(psum))

	case header.UDPProtocolNumber:
		if len(l4Buf) < header.UDPMinimumSize {
			return
		}
		udp := header.UDP(l4Buf)
		udp.SetChecksum(0)
		payload := l4Buf[header.UDPMinimumSize:]
		psum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcAddr, dstAddr, l4Len)
		psum = checksum.Checksum(payload, psum)
		xsum := ^udp.CalculateChecksum(psum)
		if xsum == 0 {
			xsum = 0xffff // RFC 768: zero means "no checksum", use 0xffff
		}
		udp.SetChecksum(xsum)
	}
}
