// Package kernelrelay is an experimental, single-peer bridge between the
// unchanged wg-quic Bind and a local kernel WireGuard UDP socket.
// It is deliberately not a production peer manager.
package kernelrelay

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"

	armorbind "github.com/RC-CHN/wg-quic/internal/bind"
	"github.com/RC-CHN/wg-quic/internal/telemetry"
	"github.com/RC-CHN/wg-quic/third_party/wireguard-go/conn"
)

const maxUDPPayload = 65507

// PeerSnapshot contains only public identity and counters. Observers must not
// expose or retain private-key or preshared-key attributes from netlink dumps.
type PeerSnapshot struct {
	PublicKey     [32]byte       `json:"-"`
	Endpoint      netip.AddrPort `json:"endpoint"`
	ListenPort    uint16         `json:"listen_port"`
	RxBytes       uint64         `json:"rx_bytes"`
	TxBytes       uint64         `json:"tx_bytes"`
	HandshakeSec  int64          `json:"handshake_sec"`
	HandshakeNsec int64          `json:"handshake_nsec"`
}

type Observer interface{ Snapshot() (PeerSnapshot, error) }

type Config struct {
	Bind             *armorbind.Bind
	Observer         Observer
	PeerPublicKey    [32]byte
	KernelEndpoint   netip.AddrPort
	BootstrapListen  netip.AddrPort
	PeerQUICEndpoint netip.AddrPort
	QUICListenPort   uint16
}

type Stats struct {
	LocalReadBatches        uint64 `json:"local_read_batches"`
	LocalReadMessages       uint64 `json:"local_read_messages"`
	LocalReadMultiMessages  uint64 `json:"local_read_multi_messages"`
	LocalReadMax            uint64 `json:"local_read_max"`
	LocalWriteBatches       uint64 `json:"local_write_batches"`
	LocalWriteMessages      uint64 `json:"local_write_messages"`
	LocalWriteMultiMessages uint64 `json:"local_write_multi_messages"`
	LocalWriteMax           uint64 `json:"local_write_max"`
	BindSendBatches         uint64 `json:"bind_send_batches"`
	BindSendMessages        uint64 `json:"bind_send_messages"`
	BindSendMultiMessages   uint64 `json:"bind_send_multi_messages"`
	BindSendMax             uint64 `json:"bind_send_max"`

	ToKernelPackets   uint64          `json:"to_kernel_packets"`
	ToKernelBytes     uint64          `json:"to_kernel_bytes"`
	FromKernelPackets uint64          `json:"from_kernel_packets"`
	FromKernelBytes   uint64          `json:"from_kernel_bytes"`
	RejectedDatagrams uint64          `json:"rejected_datagrams"`
	RejectedSessions  uint64          `json:"rejected_sessions"`
	Authenticated     bool            `json:"authenticated"`
	SessionID         uint64          `json:"session_id"`
	Bootstrap         netip.AddrPort  `json:"bootstrap"`
	Ingress           netip.AddrPort  `json:"ingress"`
	Transport         telemetry.Stats `json:"transport"`
}

type Relay struct {
	cfg                                                                    Config
	bootstrap, ingress                                                     *net.UDPConn
	bootstrapBatch, ingressBatch                                           batchSocket
	receive                                                                conn.ReceiveFunc
	configured                                                             conn.Endpoint
	initial                                                                PeerSnapshot
	mu                                                                     sync.Mutex
	sessionID                                                              uint64
	sessionEndpoint                                                        conn.Endpoint
	forwarded                                                              bool
	authenticated                                                          bool
	toPackets, toBytes, fromPackets, fromBytes, rejected, rejectedSessions atomic.Uint64
	closeOnce                                                              sync.Once
	closed                                                                 chan struct{}
	running                                                                atomic.Bool
	localReadBatches, localReadMessages, localReadMulti, localReadMax      atomic.Uint64
	localWriteBatches, localWriteMessages, localWriteMulti, localWriteMax  atomic.Uint64
	bindSendBatches, bindSendMessages, bindSendMulti, bindSendMax          atomic.Uint64
}

// Open verifies the single peer before creating a fresh ingress socket. Its
// port must never be set as the peer's endpoint by the experiment controller:
// only WireGuard's authenticated roaming may select that port.
func Open(cfg Config) (_ *Relay, err error) {
	if cfg.Bind == nil || cfg.Observer == nil || cfg.PeerPublicKey == ([32]byte{}) {
		return nil, errors.New("bind, kernel observer and nonzero peer key are required")
	}
	for name, addr := range map[string]netip.AddrPort{"kernel": cfg.KernelEndpoint, "bootstrap": cfg.BootstrapListen} {
		if !addr.IsValid() || !addr.Addr().Is4() || !addr.Addr().IsLoopback() || addr.Port() == 0 {
			return nil, fmt.Errorf("%s must be a fixed IPv4 loopback UDP endpoint", name)
		}
	}
	if cfg.KernelEndpoint == cfg.BootstrapListen || !cfg.PeerQUICEndpoint.IsValid() || cfg.PeerQUICEndpoint.Port() == 0 {
		return nil, errors.New("distinct local sockets and a numeric QUIC peer endpoint are required")
	}
	initial, err := cfg.Observer.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("initial kernel observation: %w", err)
	}
	if initial.PublicKey != cfg.PeerPublicKey || initial.ListenPort != cfg.KernelEndpoint.Port() {
		return nil, errors.New("kernel peer identity or listen port does not match")
	}
	if initial.Endpoint.IsValid() && initial.Endpoint != cfg.BootstrapListen {
		return nil, errors.New("kernel peer endpoint must be unset or the bootstrap socket")
	}
	r := &Relay{cfg: cfg, initial: initial, closed: make(chan struct{})}
	defer func() {
		if err != nil {
			r.Close()
		}
	}()
	r.bootstrap, err = net.DialUDP("udp4", net.UDPAddrFromAddrPort(cfg.BootstrapListen), net.UDPAddrFromAddrPort(cfg.KernelEndpoint))
	if err != nil {
		return nil, err
	}
	r.ingress, err = net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, net.UDPAddrFromAddrPort(cfg.KernelEndpoint))
	if err != nil {
		return nil, err
	}
	r.bootstrapBatch = ipv4.NewPacketConn(r.bootstrap)
	r.ingressBatch = ipv4.NewPacketConn(r.ingress)
	// Refuse stale endpoint evidence, even if the allocator reused a port from
	// an earlier process. No packet has been injected from ingress yet.
	check, err := cfg.Observer.Snapshot()
	if err != nil {
		return nil, err
	}
	if check.PublicKey != initial.PublicKey || check.Endpoint != initial.Endpoint || check.RxBytes != initial.RxBytes ||
		check.HandshakeSec != initial.HandshakeSec || check.HandshakeNsec != initial.HandshakeNsec {
		return nil, errors.New("kernel state changed during relay startup; use fresh isolated peers")
	}
	funcs, _, err := cfg.Bind.Open(cfg.QUICListenPort)
	if err != nil {
		return nil, err
	}
	if len(funcs) != 1 {
		return nil, errors.New("unexpected Bind receive function count")
	}
	r.receive = funcs[0]
	r.configured, err = cfg.Bind.ParseEndpoint(cfg.PeerQUICEndpoint.String())
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Relay) Close() {
	r.closeOnce.Do(func() {
		close(r.closed)
		if r.bootstrap != nil {
			r.bootstrap.Close()
		}
		if r.ingress != nil {
			r.ingress.Close()
		}
		r.cfg.Bind.Close()
	})
}

// Run owns all forwarding workers. Any I/O/observer failure closes the relay;
// it does not silently retry a changed session or infer authentication.
func (r *Relay) Run(ctx context.Context) error {
	if !r.running.CompareAndSwap(false, true) {
		return errors.New("relay Run called twice")
	}
	defer r.Close()
	errs := make(chan error, 4)
	var workers sync.WaitGroup
	for _, f := range []func() error{r.receiveQUIC, func() error { return r.receiveKernel(r.bootstrap, true) }, func() error { return r.receiveKernel(r.ingress, false) }, r.observe} {
		workers.Add(1)
		go func() { defer workers.Done(); errs <- f() }()
	}
	var err error
	select {
	case err = <-errs:
	case <-ctx.Done():
		err = ctx.Err()
	case <-r.closed:
		err = net.ErrClosed
	}
	r.Close()
	workers.Wait()
	return err
}

func (r *Relay) Stats() Stats {
	r.mu.Lock()
	s := Stats{Authenticated: r.authenticated, SessionID: r.sessionID}
	r.mu.Unlock()
	s.ToKernelPackets, s.ToKernelBytes = r.toPackets.Load(), r.toBytes.Load()
	s.FromKernelPackets, s.FromKernelBytes = r.fromPackets.Load(), r.fromBytes.Load()
	s.RejectedDatagrams, s.RejectedSessions = r.rejected.Load(), r.rejectedSessions.Load()
	s.Bootstrap = r.bootstrap.LocalAddr().(*net.UDPAddr).AddrPort()
	s.Ingress = r.ingress.LocalAddr().(*net.UDPAddr).AddrPort()
	s.LocalReadBatches, s.LocalReadMessages = r.localReadBatches.Load(), r.localReadMessages.Load()
	s.LocalReadMultiMessages, s.LocalReadMax = r.localReadMulti.Load(), r.localReadMax.Load()
	s.LocalWriteBatches, s.LocalWriteMessages = r.localWriteBatches.Load(), r.localWriteMessages.Load()
	s.LocalWriteMultiMessages, s.LocalWriteMax = r.localWriteMulti.Load(), r.localWriteMax.Load()
	s.BindSendBatches, s.BindSendMessages = r.bindSendBatches.Load(), r.bindSendMessages.Load()
	s.BindSendMultiMessages, s.BindSendMax = r.bindSendMulti.Load(), r.bindSendMax.Load()
	s.Transport = r.cfg.Bind.Stats()
	return s
}

// WireGuard packet shape validation is only a size/boundary check. It NEVER
// proves authentication. Cryptography, replay and AllowedIPs remain in WG.
func validDatagram(packet []byte) bool {
	if len(packet) < 4 || len(packet) > maxUDPPayload {
		return false
	}
	switch binary.LittleEndian.Uint32(packet[:4]) {
	case 1:
		return len(packet) == 148
	case 2:
		return len(packet) == 92
	case 3:
		return len(packet) == 64
	case 4:
		return len(packet) >= 32
	default:
		return false
	}
}

func (r *Relay) receiveQUIC() error {
	packets := make([][]byte, r.cfg.Bind.BatchSize())
	messages := make([]ipv4.Message, len(packets))
	for i := range packets {
		packets[i] = make([]byte, 65535)
		messages[i].Buffers = make([][]byte, 1)
	}
	sizes := make([]int, len(packets))
	eps := make([]conn.Endpoint, len(packets))
	for {
		n, readErr := r.receive(packets, sizes, eps)
		if readErr != nil {
			return readErr
		}
		if n < 0 || n > len(packets) {
			return errors.New("invalid Bind receive count")
		}
		count := r.prepareKernelBatch(packets, sizes, eps, messages, n)
		if count > 0 {
			result, err := writeLocalBatch(r.ingressBatch, messages[:count])
			r.toPackets.Add(uint64(result.packets))
			r.toBytes.Add(uint64(result.bytes))
			r.localWriteBatches.Add(uint64(result.batches))
			r.localWriteMessages.Add(uint64(result.packets))
			r.localWriteMulti.Add(uint64(result.multiPackets))
			recordMaximum(&r.localWriteMax, uint64(result.maxBatch))
			if err != nil {
				return fmt.Errorf("deliver batch to kernel: %w", err)
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (r *Relay) acceptEndpoint(endpoint conn.Endpoint) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.acceptEndpointLocked(endpoint)
}

// Caller holds mu. Numeric address + port comparison preserves exact endpoint
// pinning, including IPv6 zones, without allocating strings for each packet.
func (r *Relay) acceptEndpointLocked(endpoint conn.Endpoint) bool {
	ep, ok := endpoint.(interface {
		SessionID() uint64
		DstAddrPort() netip.AddrPort
	})
	if !ok {
		return false
	}
	address := ep.DstAddrPort()
	if !address.IsValid() || address != r.cfg.PeerQUICEndpoint {
		return false
	}
	id := ep.SessionID()
	if id == 0 || (r.sessionID != 0 && r.sessionID != id) {
		return false
	}
	r.sessionID, r.sessionEndpoint = id, endpoint
	return true
}

func (r *Relay) prepareKernelBatch(packets [][]byte, sizes []int, endpoints []conn.Endpoint, messages []ipv4.Message, n int) int {
	count, rejected, sessions := 0, uint64(0), uint64(0)
	r.mu.Lock()
	for i := 0; i < n; i++ {
		if sizes[i] < 0 || sizes[i] > len(packets[i]) || !validDatagram(packets[i][:sizes[i]]) {
			rejected++
			continue
		}
		if !r.acceptEndpointLocked(endpoints[i]) {
			sessions++
			continue
		}
		messages[count].Buffers[0] = packets[i][:sizes[i]]
		messages[count].N = 0
		messages[count].Addr = nil
		count++
	}
	// Set before writing, just as in the single-packet path. Netlink evidence
	// of a fresh ingress endpoint AND RX progress is still required to admit WG.
	if count > 0 {
		r.forwarded = true
	}
	r.mu.Unlock()
	if rejected > 0 {
		r.rejected.Add(rejected)
	}
	if sessions > 0 {
		r.rejectedSessions.Add(sessions)
	}
	return count
}

func (r *Relay) receiveKernel(socket *net.UDPConn, bootstrap bool) error {
	io := r.ingressBatch
	if bootstrap {
		io = r.bootstrapBatch
	}
	messages := make([]ipv4.Message, localBatchSize)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, 65536)}
	}
	packets := make([][]byte, 0, len(messages))
	for {
		n, readErr := readLocalBatch(io, messages)
		if n > 0 {
			r.localReadBatches.Add(1)
			r.localReadMessages.Add(uint64(n))
			if n > 1 {
				r.localReadMulti.Add(uint64(n))
			}
			recordMaximum(&r.localReadMax, uint64(n))
		}
		packets = packets[:0]
		rejected := uint64(0)
		bytes := uint64(0)
		for i := 0; i < n; i++ {
			packet, valid := localPacket(messages[i], r.cfg.KernelEndpoint)
			if !valid {
				rejected++
				continue
			}
			packets = append(packets, packet)
			bytes += uint64(len(packet))
		}
		if rejected > 0 {
			r.rejected.Add(rejected)
		}
		if len(packets) > 0 {
			r.mu.Lock()
			ep, authenticated := r.sessionEndpoint, r.authenticated
			r.mu.Unlock()
			if bootstrap {
				if authenticated {
					return errors.New("kernel unexpectedly returned to bootstrap endpoint")
				}
				ep = r.configured
			}
			if ep == nil {
				return errors.New("kernel replied without an ingress session")
			}
			// Bind.Send synchronously copies each payload into its own send buffer.
			// No receive buffer is reused until the entire batch has been consumed.
			if err := r.cfg.Bind.Send(packets, ep); err != nil {
				return err
			}
			r.fromPackets.Add(uint64(len(packets)))
			r.fromBytes.Add(bytes)
			r.bindSendBatches.Add(1)
			r.bindSendMessages.Add(uint64(len(packets)))
			if len(packets) > 1 {
				r.bindSendMulti.Add(uint64(len(packets)))
			}
			recordMaximum(&r.bindSendMax, uint64(len(packets)))
		}
		if readErr != nil {
			return readErr
		}
	}
}

func authenticatedProgress(initial, current PeerSnapshot, key [32]byte, ingress netip.AddrPort) bool {
	if current.PublicKey != key || initial.PublicKey != key || current.ListenPort != initial.ListenPort ||
		!ingress.IsValid() || initial.Endpoint == ingress || current.Endpoint != ingress || current.RxBytes <= initial.RxBytes {
		return false
	}
	return true
}

func (r *Relay) observe() error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.closed:
			return net.ErrClosed
		case <-ticker.C:
		}
		r.mu.Lock()
		pending := r.forwarded && !r.authenticated
		sessionID := r.sessionID
		r.mu.Unlock()
		if !pending {
			continue
		}
		current, err := r.cfg.Observer.Snapshot()
		if err != nil {
			return fmt.Errorf("kernel authentication observation: %w", err)
		}
		if current.PublicKey != r.cfg.PeerPublicKey || current.ListenPort != r.initial.ListenPort || current.RxBytes < r.initial.RxBytes {
			return errors.New("kernel peer changed during relay lifetime")
		}
		ingress := r.ingress.LocalAddr().(*net.UDPAddr).AddrPort()
		if !authenticatedProgress(r.initial, current, r.cfg.PeerPublicKey, ingress) {
			continue
		}
		if !r.cfg.Bind.AssociateSessionPeer(sessionID, hex.EncodeToString(r.cfg.PeerPublicKey[:]), 1) {
			return errors.New("authenticated kernel endpoint belongs to a closed QUIC session")
		}
		r.mu.Lock()
		r.authenticated = true
		r.mu.Unlock()
		// The fixed-peer experiment prohibits concurrent administrator
		// changes. No poll/exec process remains in the measured steady path.
		<-r.closed
		return net.ErrClosed
	}
}
