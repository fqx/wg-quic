package kernelrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	armorbind "github.com/RC-CHN/wg-quic/internal/bind"
	"github.com/RC-CHN/wg-quic/third_party/wireguard-go/conn"
)

type testObserver struct {
	mu    sync.Mutex
	value PeerSnapshot
	err   error
}

func (o *testObserver) Snapshot() (PeerSnapshot, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.value, o.err
}
func (o *testObserver) set(value PeerSnapshot) { o.mu.Lock(); o.value = value; o.mu.Unlock() }

func TestAuthenticatedProgressRequiresFreshEndpointAndRX(t *testing.T) {
	key := [32]byte{1}
	bootstrap := netip.MustParseAddrPort("127.0.0.1:30001")
	ingress := netip.MustParseAddrPort("127.0.0.1:30002")
	initial := PeerSnapshot{PublicKey: key, Endpoint: bootstrap, ListenPort: 1234, RxBytes: 100, HandshakeSec: 100}
	valid := initial
	valid.Endpoint = ingress
	valid.RxBytes++
	if !authenticatedProgress(initial, valid, key, ingress) {
		t.Fatal("fresh authenticated progress rejected")
	}
	for name, change := range map[string]func(*PeerSnapshot){
		"static configured endpoint": func(s *PeerSnapshot) { s.Endpoint = bootstrap },
		"old RX":                     func(s *PeerSnapshot) { s.RxBytes = initial.RxBytes },
		"counter reset":              func(s *PeerSnapshot) { s.RxBytes = 0 },
		"wrong peer":                 func(s *PeerSnapshot) { s.PublicKey[1]++ },
		"wrong listen socket":        func(s *PeerSnapshot) { s.ListenPort++ },
		"handshake timestamp alone":  func(s *PeerSnapshot) { s.Endpoint = bootstrap; s.HandshakeSec++; s.RxBytes++ },
	} {
		t.Run(name, func(t *testing.T) {
			current := valid
			change(&current)
			if authenticatedProgress(initial, current, key, ingress) {
				t.Fatal("unproven authentication accepted")
			}
		})
	}
	stale := initial
	stale.Endpoint = ingress
	if authenticatedProgress(stale, valid, key, ingress) {
		t.Fatal("reused preconfigured socket accepted")
	}
}

func TestWireGuardDatagramBoundaries(t *testing.T) {
	for _, tc := range []struct {
		kind uint32
		size int
		want bool
	}{
		{1, 148, true}, {1, 147, false}, {1, 149, false}, {2, 92, true}, {2, 91, false}, {3, 64, true}, {3, 63, false},
		{4, 32, true}, {4, 31, false}, {4, 1456, true}, {4, 65507, true}, {4, 65508, false}, {0x1000001, 148, false}, {5, 148, false},
	} {
		packet := make([]byte, tc.size)
		binary.LittleEndian.PutUint32(packet, tc.kind)
		if got := validDatagram(packet); got != tc.want {
			t.Errorf("kind=%d size=%d: %v", tc.kind, tc.size, got)
		}
	}
	if validDatagram(nil) || validDatagram([]byte{1, 0, 0}) {
		t.Fatal("short datagram accepted")
	}
}

func udpSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	return socket
}

func freeUDPAddress(t *testing.T) netip.AddrPort {
	socket := udpSocket(t)
	addr := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	socket.Close()
	return addr
}

func TestRelayPreservesDatagramsAndRequiresKernelEvidence(t *testing.T) {
	// The "kernel" here is explicitly a UDP fixture. This test proves relay
	// state and boundaries; it is not evidence of kernel WG authentication.
	kernel := udpSocket(t)
	remote := armorbind.New(armorbind.DefaultConfig())
	remoteReceivers, remotePort, err := remote.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	key := [32]byte{1}
	observer := &testObserver{value: PeerSnapshot{PublicKey: key, ListenPort: kernel.LocalAddr().(*net.UDPAddr).AddrPort().Port()}}
	bind := armorbind.New(armorbind.DefaultConfig())
	relay, err := Open(Config{Bind: bind, Observer: observer, PeerPublicKey: key,
		KernelEndpoint: kernel.LocalAddr().(*net.UDPAddr).AddrPort(), BootstrapListen: freeUDPAddress(t),
		PeerQUICEndpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), remotePort)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- relay.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("relay workers did not terminate")
		}
	}()
	ep, err := remote.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bind.Port()).String())
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1456)
	binary.LittleEndian.PutUint32(packet, 4)
	for i := 4; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	if err := remote.Send([][]byte{packet}, ep); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65536)
	kernel.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, source, err := kernel.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], packet) || source != relay.Stats().Ingress {
		t.Fatal("datagram changed or wrong source socket")
	}
	// Simulated RX progress at the configured bootstrap port proves nothing.
	unproven := observer.value
	unproven.RxBytes = 1456
	unproven.Endpoint = relay.Stats().Bootstrap
	unproven.HandshakeSec = time.Now().Unix()
	observer.set(unproven)
	time.Sleep(150 * time.Millisecond)
	if relay.Stats().Authenticated {
		t.Fatal("bootstrap state was treated as authenticated")
	}
	// A reply does not authenticate either, but must use the same QUIC session.
	if _, err := kernel.WriteToUDPAddrPort(packet, source); err != nil {
		t.Fatal(err)
	}
	result := make(chan []byte, 1)
	go func() {
		bufs := [][]byte{make([]byte, 65535)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := remoteReceivers[0](bufs, sizes, eps)
		if err == nil && n == 1 {
			result <- bufs[0][:sizes[0]]
		}
	}()
	select {
	case got := <-result:
		if !bytes.Equal(got, packet) {
			t.Fatal("reply changed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply")
	}
	if relay.Stats().Authenticated {
		t.Fatal("UDP response authenticated the session")
	}
	proven := unproven
	proven.Endpoint = source
	observer.set(proven)
	deadline := time.Now().Add(time.Second)
	for !relay.Stats().Authenticated && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !relay.Stats().Authenticated {
		t.Fatal("kernel evidence did not admit session")
	}
	if relay.Stats().Transport.AuthenticationTimeouts != 0 {
		t.Fatal("unexpected authentication expiry")
	}
	// Forged local traffic from another socket is rejected by connected UDP.
	stranger := udpSocket(t)
	if _, err := stranger.WriteToUDPAddrPort(packet, source); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if relay.Stats().FromKernelPackets != 1 {
		t.Fatal("wrong local source was forwarded")
	}
}

func TestRelayRejectsUntrustedInitialState(t *testing.T) {
	key := [32]byte{1}
	kernel := udpSocket(t)
	kernelAddr := kernel.LocalAddr().(*net.UDPAddr).AddrPort()
	base := Config{Bind: armorbind.New(armorbind.DefaultConfig()), PeerPublicKey: key, KernelEndpoint: kernelAddr, BootstrapListen: freeUDPAddress(t), PeerQUICEndpoint: netip.MustParseAddrPort("127.0.0.1:12345")}
	for _, state := range []PeerSnapshot{
		{PublicKey: [32]byte{2}, ListenPort: kernelAddr.Port()},
		{PublicKey: key, ListenPort: kernelAddr.Port() + 1},
		{PublicKey: key, ListenPort: kernelAddr.Port(), Endpoint: netip.MustParseAddrPort("127.0.0.1:23456")},
	} {
		cfg := base
		cfg.Observer = &testObserver{value: state}
		if relay, err := Open(cfg); err == nil {
			relay.Close()
			t.Fatal("untrusted initial state accepted")
		}
	}
	base.Observer = &testObserver{err: errors.New("netlink unavailable")}
	if relay, err := Open(base); err == nil {
		relay.Close()
		t.Fatal("missing observer accepted")
	}
}

type testEndpoint struct {
	address netip.AddrPort
	id      uint64
}

func (e testEndpoint) ClearSrc()           {}
func (e testEndpoint) SrcToString() string { return "" }
func (e testEndpoint) DstToString() string { return e.address.String() }
func (e testEndpoint) DstToBytes() []byte  { return nil }
func (e testEndpoint) DstIP() netip.Addr   { return e.address.Addr() }
func (e testEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e testEndpoint) SessionID() uint64   { return e.id }

func TestSessionPinRejectsReplacementAndOuterMigration(t *testing.T) {
	address := netip.MustParseAddrPort("127.0.0.1:34567")
	relay := &Relay{cfg: Config{PeerQUICEndpoint: address}}
	if relay.acceptEndpoint(nil) || relay.acceptEndpoint(testEndpoint{address, 0}) {
		t.Fatal("missing session accepted")
	}
	if !relay.acceptEndpoint(testEndpoint{address, 1}) || !relay.acceptEndpoint(testEndpoint{address, 1}) {
		t.Fatal("fixed session rejected")
	}
	if relay.acceptEndpoint(testEndpoint{address, 2}) {
		t.Fatal("replacement session accepted")
	}
	if relay.acceptEndpoint(testEndpoint{netip.MustParseAddrPort("127.0.0.1:34568"), 1}) {
		t.Fatal("unconfigured migration accepted")
	}
	if relay.sessionID != 1 {
		t.Fatal("session changed on rejection")
	}
}
