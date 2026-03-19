// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/socket"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// broadcastRelayIdleTimeout is the amount of idle time without pending requests before the
	// UDP socket and read loop are closed.
	broadcastRelayIdleTimeout = 1 * time.Minute
)

type relayKey struct {
	xid    dhcpv4.TransactionID
	chaddr string
}

// broadcastRelay forwards DHCP requests to IPv4 broadcast on the given interface.
type broadcastRelay struct {
	log   *slog.Logger
	netns *netns.NetNS

	ifname      string
	ifindex     int
	ifmac       net.HardwareAddr
	idleTimeout time.Duration

	mu         lock.Mutex
	pending    map[relayKey]chan *dhcpv4.DHCPv4
	conn       *socket.Conn
	lastActive time.Time
}

// broadcastRelayFactory returns a BroadcastRelay for each workload.
type broadcastRelayFactory struct {
	relay *broadcastRelay
}

// RelayFor implements RelayFactory.
func (f *broadcastRelayFactory) RelayFor(*tables.LocalWorkload) (Relayer, error) {
	return f.relay, nil
}

// Relay forwards the DHCP request and returns the first matching response.
func (r *broadcastRelay) Relay(ctx context.Context, waitTime time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	if req == nil {
		return nil, errors.New("dhcp request is nil")
	}

	if err := r.ensureConn(); err != nil {
		return nil, err
	}

	timeout := waitTime
	if ctxDeadline, ok := ctx.Deadline(); ok {
		ctxTimeout := time.Until(ctxDeadline)
		if ctxTimeout <= 0 {
			return nil, ctx.Err()
		}
		if timeout <= 0 || ctxTimeout < timeout {
			timeout = ctxTimeout
		}
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("wait time is required")
	}

	key := relayKey{
		xid:    req.TransactionID,
		chaddr: req.ClientHWAddr.String(),
	}
	respCh := make(chan *dhcpv4.DHCPv4, 16)
	r.addPending(key, respCh)
	defer r.removePending(key)

	if req.MessageType() == dhcpv4.MessageTypeRequest &&
		req.ClientIPAddr != nil && !req.ClientIPAddr.IsUnspecified() {
		// Turn unicast renewals into a broadcast "init-reboot" request by filling the
		// "requested IP address" option and unsetting the client IP.
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(req.ClientIPAddr))(req)
		req.ClientIPAddr = nil
	}
	// Set broadcast bit to request responses via broadcast.
	req.SetBroadcast()

	r.log.Debug("Relaying DHCP request",
		logfields.Type, req.MessageType(),
		logfields.Xid, req.TransactionID,
		logfields.Chaddr, req.ClientHWAddr,
		logfields.Interface, r.ifname,
		logfields.Timeout, waitTime,
	)

	if err := r.send(ctx, req); err != nil {
		r.log.Info("Failed to send broadcast DHCP request", logfields.Error, err)
		return nil, fmt.Errorf("send broadcast request: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var responses []*dhcpv4.DHCPv4
	for {
		select {
		case <-ctx.Done():
			r.log.Info("DHCP relay context done", logfields.Error, ctx.Err())
			return responses, ctx.Err()
		case <-timer.C:
			if len(responses) == 0 {
				r.log.Info("Timed out waiting for DHCP response")
				return nil, fmt.Errorf("timed out waiting for DHCP response")
			}
			r.log.Debug("Returning responses",
				logfields.Count, len(responses),
			)
			return responses, nil
		case resp := <-respCh:
			if resp == nil {
				r.log.Info("Received empty DHCP response")
				continue
			}
			r.log.Debug("Received DHCP response",
				logfields.Type, resp.MessageType(),
				logfields.Xid, resp.TransactionID,
				logfields.IPv4, resp.YourIPAddr,
				logfields.Interface, r.ifname,
			)
			responses = append(responses, resp)
		}
	}
}

func (r *broadcastRelay) prepare(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	copyReq, err := dhcpv4.FromBytes(req.ToBytes())
	if err != nil {
		return nil, fmt.Errorf("copy dhcp request: %w", err)
	}
	copyReq.SetBroadcast()
	return copyReq, nil
}

func (r *broadcastRelay) ensureInterface() error {
	if r.ifname == "" {
		return errors.New("interface name is required")
	}
	link, err := safenetlink.LinkByName(r.ifname)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", r.ifname, err)
	}
	attrs := link.Attrs()
	if attrs == nil || len(attrs.HardwareAddr) != 6 {
		return fmt.Errorf("interface %q has no hardware address", r.ifname)
	}
	if attrs.Flags&net.FlagUp == 0 || attrs.Flags&net.FlagRunning == 0 {
		return fmt.Errorf("interface %q is down", r.ifname)
	}
	r.ifindex = attrs.Index
	r.ifmac = attrs.HardwareAddr
	return nil
}

func (r *broadcastRelay) ensureConn() error {
	r.mu.Lock()
	if r.conn != nil {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	var conn *socket.Conn
	if err := r.withNetNS(func() error {
		if err := r.ensureInterface(); err != nil {
			return err
		}
		var err error
		conn, err = newRelaySocket(r.ifindex, dhcpv4.ClientPort)
		return err
	}); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		_ = conn.Close()
		return nil
	}
	r.conn = conn
	r.pending = make(map[relayKey]chan *dhcpv4.DHCPv4)
	r.lastActive = time.Now()
	if r.idleTimeout <= 0 {
		r.idleTimeout = broadcastRelayIdleTimeout
	}
	go r.readLoop()
	return nil
}

func (r *broadcastRelay) withNetNS(fn func() error) error {
	if r.netns == nil {
		return fn()
	}
	return r.netns.Do(fn)
}

func (r *broadcastRelay) addPending(key relayKey, ch chan *dhcpv4.DHCPv4) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = make(map[relayKey]chan *dhcpv4.DHCPv4)
	}
	r.pending[key] = ch
	r.lastActive = time.Now()
}

func (r *broadcastRelay) removePending(key relayKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, key)
}

func (r *broadcastRelay) readLoop() {
	buf := make([]byte, 1500)
	for {
		if err := r.conn.SetReadDeadline(time.Now().Add(r.idleTimeout)); err != nil {
			r.log.Error("Failed to set read deadline", logfields.Error, err)
			r.closeConn()
			return
		}
		n, _, err := r.conn.Recvfrom(context.Background(), buf, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if r.shouldCloseIdle() {
					r.log.Debug("Closing idle DHCP relay socket")
					r.closeConn()
					return
				}
				continue
			}
			r.log.Error("Failed to read DHCP response", logfields.Error, err)
			return
		}

		r.markActive()
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if ipLayer == nil || udpLayer == nil {
			continue
		}
		udp := udpLayer.(*layers.UDP)
		if udp.DstPort != layers.UDPPort(dhcpv4.ClientPort) {
			continue
		}
		resp, err := dhcpv4.FromBytes(udp.Payload)
		if err != nil {
			r.log.Error("Failed to parse DHCP response", logfields.Error, err)
			continue
		}
		key := relayKey{
			xid:    resp.TransactionID,
			chaddr: resp.ClientHWAddr.String(),
		}
		r.mu.Lock()
		ch := r.pending[key]
		r.mu.Unlock()
		if ch == nil {
			continue
		}
		select {
		case ch <- resp:
		default:
		}
	}
}

func (r *broadcastRelay) markActive() {
	r.mu.Lock()
	r.lastActive = time.Now()
	r.mu.Unlock()
}

func (r *broadcastRelay) shouldCloseIdle() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) != 0 {
		return false
	}
	return time.Since(r.lastActive) >= r.idleTimeout
}

func (r *broadcastRelay) closeConn() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		_ = r.conn.Close()
	}
	r.conn = nil
	r.ifindex = 0
	r.ifmac = nil
	r.pending = nil
}

func (r *broadcastRelay) send(ctx context.Context, req *dhcpv4.DHCPv4) error {
	if err := r.ensureConn(); err != nil {
		return err
	}

	prepared, err := r.prepare(req)
	if err != nil {
		return err
	}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame, err := buildServerDHCPFrame(
		prepared.ToBytes(),
		r.ifmac,
		dstMAC,
		net.IPv4zero,
		net.IPv4bcast,
		dhcpv4.ClientPort,
		dhcpv4.ServerPort,
	)
	if err != nil {
		return err
	}

	sll := &unix.SockaddrLinklayer{
		Ifindex:  r.ifindex,
		Protocol: htons(unix.ETH_P_IP),
		Halen:    6,
	}
	copy(sll.Addr[:], dstMAC)
	return r.conn.Sendto(ctx, frame, 0, sll)
}

func newRelaySocket(ifindex int, dstPort int) (*socket.Conn, error) {
	conn, err := socket.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)), "privnet-dhcp-relay", nil)
	if err != nil {
		return nil, err
	}
	if ifindex > 0 {
		sll := &unix.SockaddrLinklayer{
			Ifindex:  ifindex,
			Protocol: htons(unix.ETH_P_IP),
		}
		if err := conn.Bind(sll); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	// Install a BPF filter to only accept unfragmented packets going to UDP and port [dstPort]
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                                   // ethertype
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.ETH_P_IP, SkipFalse: 8},    // IPv4
		bpf.LoadAbsolute{Off: 23, Size: 1},                                   // IP proto
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_UDP, SkipFalse: 6}, // UDP
		bpf.LoadAbsolute{Off: 20, Size: 2},                                   // flags/frag offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4},          // drop fragments
		bpf.LoadMemShift{Off: 14},                                            // X = IP header len
		bpf.LoadIndirect{Off: 16, Size: 2},                                   // UDP dst port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipFalse: 1},
		bpf.RetConstant{Val: 4096}, // accept 4k bytes
		bpf.RetConstant{Val: 0},    // drop
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetBPF(filter); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
