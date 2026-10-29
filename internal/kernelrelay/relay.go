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
	for i := range packets {
		packets[i] = make([]byte, 65535)
	}
	sizes := make([]int, len(packets))
	eps := make([]conn.Endpoint, len(packets))
	for {
		n, err := r.receive(packets, sizes, eps)
		if err != nil {
			return err
		}
		for i := range n {
			packet := packets[i][:sizes[i]]
			if !validDatagram(packet) {
				r.rejected.Add(1)
				continue
			}
			if !r.acceptEndpoint(eps[i]) {
				r.rejectedSessions.Add(1)
				continue
			}
			r.mu.Lock()
			// Set before write: the observer also requires a new endpoint and
			// kernel receive progress; neither can be caused by this boolean.
			r.forwarded = true
			r.mu.Unlock()
			written, err := r.ingress.Write(packet)
			if err != nil {
				return fmt.Errorf("deliver to kernel: %w", err)
			}
			if written != len(packet) {
				return errors.New("short UDP write to kernel")
			}
			r.toPackets.Add(1)
			r.toBytes.Add(uint64(written))
		}
	}
}

func (r *Relay) acceptEndpoint(endpoint conn.Endpoint) bool {
	ep, ok := endpoint.(interface{ SessionID() uint64 })
	if !ok || ep.SessionID() == 0 || endpoint.DstToString() != r.cfg.PeerQUICEndpoint.String() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessionID != 0 && r.sessionID != ep.SessionID() {
		return false
	}
	r.sessionID, r.sessionEndpoint = ep.SessionID(), endpoint
	return true
}

func (r *Relay) receiveKernel(socket *net.UDPConn, bootstrap bool) error {
	// A 65536-byte buffer exceeds every IPv4 UDP payload. Oversized input is
	// rejected whole; the relay never forwards a truncated prefix.
	buffer := make([]byte, 65536)
	for {
		n, err := socket.Read(buffer)
		if err != nil {
			return err
		}
		if !validDatagram(buffer[:n]) {
			r.rejected.Add(1)
			continue
		}
		r.mu.Lock()
		ep := r.sessionEndpoint
		authenticated := r.authenticated
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
		if err := r.cfg.Bind.Send([][]byte{buffer[:n]}, ep); err != nil {
			return err
		}
		r.fromPackets.Add(1)
		r.fromBytes.Add(uint64(n))
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
