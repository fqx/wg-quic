//go:build !windows

package armorbind

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
)

// Faults apply to outer UDP, including TLS and WireGuard handshakes. These are
// correctness tests with real WireGuard/QUIC and an in-memory TUN, not bandwidth
// measurements: the proxy allocates and schedules packets in userspace.
type faultProfile struct {
	loss, reverseLoss       int // percent, independently sampled in each direction
	delay, reverseDelay     time.Duration
	jitter                  time.Duration
	burstEvery, burstLength uint64
	reorderEvery            uint64
	blackhole               int // 1 forward, 2 reverse, 3 both
}

type faultPath struct {
	mu      sync.Mutex
	profile faultProfile
	random  *rand.Rand
	counts  [2]uint64
	dropped atomic.Uint64
}

func (p *faultPath) set(profile faultProfile) {
	p.mu.Lock()
	p.profile = profile
	p.mu.Unlock()
}

func (p *faultPath) drop(dir quicproxy.Direction, _, _ net.Addr, _ []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := int(dir)
	p.counts[i]++
	f := p.profile
	loss := f.loss
	if i == 1 {
		loss = f.reverseLoss
	}
	drop := f.blackhole&(1<<i) != 0 || p.random.IntN(100) < loss ||
		(f.burstEvery > 0 && (p.counts[i]-1)%f.burstEvery < f.burstLength)
	if drop {
		p.dropped.Add(1)
	}
	return drop
}

func (p *faultPath) delay(dir quicproxy.Direction, _, _ net.Addr, _ []byte) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := p.profile
	d := f.delay
	if dir == quicproxy.DirectionOutgoing {
		d = f.reverseDelay
	}
	if f.jitter > 0 {
		d += time.Duration(p.random.Int64N(int64(2*f.jitter)+1)) - f.jitter
	}
	if f.reorderEvery > 0 && p.counts[int(dir)]%f.reorderEvery == 0 {
		d += 40 * time.Millisecond
	}
	return max(0, d)
}

func impairedPair(t *testing.T, profile faultProfile, cfg Config) ([2]*behaviorPeer, *faultPath) {
	t.Helper()
	key := randomTestKey(t)
	peers := newBehaviorPairWithConfig(t, [2][32]byte{key, key}, key[:], cfg, false)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	path := &faultPath{profile: profile, random: rand.New(rand.NewPCG(17, 93))}
	proxy := &quicproxy.Proxy{
		Conn:       socket,
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(peers[1].bind.Port())},
		DropPacket: path.drop, DelayPacket: path.delay,
	}
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })
	if err := peers[0].dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", peers[1].publicKey, proxy.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	return peers, path
}

// Retry application probes because a datagram tunnel is deliberately unreliable.
// Success means the exact plaintext arrived; QUIC establishment alone is not
// sufficient. Tags distinguish phases so delayed pre-outage data cannot pass.
func probeImpaired(t *testing.T, source, destination *behaviorPeer, tag uint16, timeout time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	packet := testIPv4Packet(source.ipv4, destination.ipv4, 900, tag)
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case <-tick.C:
			select {
			case source.tun.Outbound <- packet:
			default:
			}
		case got := <-destination.tun.Inbound:
			if bytes.Equal(got, packet) {
				return time.Since(start)
			}
			// Previous probes can still be queued. They cannot satisfy this
			// phase's delivery check; the normal full-payload tests cover
			// corruption separately.
		case <-deadline.C:
			t.Fatalf("no verified delivery for phase %d within %s; source=%+v destination=%+v",
				tag, timeout, source.bind.Stats(), destination.bind.Stats())
			return 0
		}
	}
}

func TestWireGuardImpairedColdStart(t *testing.T) {
	if testing.Short() {
		t.Skip("extended outer-network fault matrix")
	}
	for _, tc := range []struct {
		name    string
		profile faultProfile
	}{
		{"clean", faultProfile{}},
		{"random_10_percent", faultProfile{loss: 10, reverseLoss: 10}},
		{"reverse_loss_25_percent", faultProfile{reverseLoss: 25, delay: 5 * time.Millisecond, reverseDelay: 25 * time.Millisecond}},
		{"burst_and_reorder", faultProfile{burstEvery: 40, burstLength: 4, reorderEvery: 5}},
		{"jitter", faultProfile{loss: 2, reverseLoss: 2, delay: 20 * time.Millisecond, reverseDelay: 20 * time.Millisecond, jitter: 18 * time.Millisecond, reorderEvery: 7}},
		{"satellite", faultProfile{delay: 300 * time.Millisecond, reverseDelay: 300 * time.Millisecond, jitter: 30 * time.Millisecond, loss: 1, reverseLoss: 1}},
	} {
		for _, fec := range []string{"off", "auto"} {
			t.Run(tc.name+"/"+fec, func(t *testing.T) {
				cfg := DefaultConfig()
				cfg.FECMode = fec
				peers, path := impairedPair(t, tc.profile, cfg)
				first := probeImpaired(t, peers[0], peers[1], 1, 20*time.Second)
				reverse := probeImpaired(t, peers[1], peers[0], 2, 10*time.Second)
				t.Logf("first_verified_delivery=%s reverse_delivery=%s outer_drops=%d", first, reverse, path.dropped.Load())
			})
		}
	}
}

func TestWireGuardOutageRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("extended outer-network fault matrix")
	}
	for _, tc := range []struct {
		name      string
		direction int
		duration  time.Duration
		cycles    int
	}{
		{"short_bidirectional", 3, 100 * time.Millisecond, 1},
		{"idle_timeout_bidirectional", 3, 1300 * time.Millisecond, 1},
		{"forward_blackhole", 1, 1300 * time.Millisecond, 1},
		{"reverse_blackhole", 2, 1300 * time.Millisecond, 1},
		{"flapping", 3, 400 * time.Millisecond, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			// Shorten only local timeout policy for a bounded CI test. The
			// container suite exercises production defaults and real TUN.
			cfg.MaxIdleTimeout = 600 * time.Millisecond
			cfg.KeepAlivePeriod = 100 * time.Millisecond
			cfg.HandshakeTimeout = 500 * time.Millisecond
			cfg.ReconnectMin, cfg.ReconnectMax = 30*time.Millisecond, 150*time.Millisecond
			peers, path := impairedPair(t, faultProfile{}, cfg)
			probeImpaired(t, peers[0], peers[1], 1, 5*time.Second)
			probeImpaired(t, peers[1], peers[0], 2, 5*time.Second)
			for i := range tc.cycles {
				before := path.dropped.Load()
				path.set(faultProfile{blackhole: tc.direction})
				time.Sleep(tc.duration)
				if path.dropped.Load() == before {
					t.Fatal("outage did not drop any outer packets")
				}
				path.set(faultProfile{loss: 2, reverseLoss: 2})
				recovery := probeImpaired(t, peers[0], peers[1], uint16(10+i*2), 8*time.Second)
				probeImpaired(t, peers[1], peers[0], uint16(11+i*2), 8*time.Second)
				t.Logf("cycle=%d verified_recovery=%s drops=%d", i, recovery, path.dropped.Load()-before)
			}
			start := time.Now()
			for _, peer := range peers {
				peer.dev.Close()
				if peer.bind.stats.activeSessions.Load() != 0 {
					t.Fatal("shutdown leaked active sessions")
				}
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("shutdown took %s", elapsed)
			}
		})
	}
}

func TestWireGuardInitiallyOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("extended outer-network fault matrix")
	}
	cfg := DefaultConfig()
	cfg.HandshakeTimeout = 200 * time.Millisecond
	cfg.ReconnectMin, cfg.ReconnectMax = 30*time.Millisecond, 100*time.Millisecond
	peers, path := impairedPair(t, faultProfile{blackhole: 3}, cfg)
	injectTUNPacket(t, peers[0].tun, testIPv4Packet(peers[0].ipv4, peers[1].ipv4, 64, 1))
	waitForCondition(t, "failed offline dial", func() bool {
		recent, _ := peers[0].bind.RecentSessionTelemetry()
		return len(recent) > 0
	})
	path.set(faultProfile{})
	first := probeImpaired(t, peers[0], peers[1], 2, 10*time.Second)
	probeImpaired(t, peers[1], peers[0], 3, 5*time.Second)
	t.Logf("online_to_first_verified_delivery=%s", first)
}

func TestWireGuardImpairedTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("extended outer-network fault matrix")
	}
	for _, tc := range []struct {
		name  string
		fault faultProfile
	}{
		{"random_loss", faultProfile{loss: 10, reverseLoss: 10}},
		{"burst_loss", faultProfile{burstEvery: 64, burstLength: 8}},
		{"reverse_starvation", faultProfile{reverseLoss: 30, reverseDelay: 50 * time.Millisecond}},
		{"reorder_jitter", faultProfile{delay: 10 * time.Millisecond, reverseDelay: 10 * time.Millisecond, jitter: 8 * time.Millisecond, reorderEvery: 3}},
	} {
		for _, fec := range []string{"off", "auto"} {
			t.Run(tc.name+"/"+fec, func(t *testing.T) {
				cfg := DefaultConfig()
				cfg.FECMode = fec
				peers, path := impairedPair(t, faultProfile{}, cfg)
				probeImpaired(t, peers[0], peers[1], 0, 5*time.Second)
				path.set(tc.fault)
				const packets = 160
				expected := make(map[string]bool, packets)
				payloads := make([][]byte, packets)
				for i := range payloads {
					// Both address families, including packets requiring
					// outer fragmentation. Verify every byte, not just a tag.
					if i%2 == 0 {
						payloads[i] = testIPv4Packet(peers[0].ipv4, peers[1].ipv4, 900, uint16(i+100))
					} else {
						payloads[i] = testIPv6Packet(peers[0].ipv6, peers[1].ipv6, 3000, uint16(i+100))
					}
					expected[string(payloads[i])] = false
				}
				done := make(chan struct{})
				cancel := make(chan struct{})
				t.Cleanup(func() { close(cancel); <-done })
				go func() {
					defer close(done)
					// Limit this integrity gate to 100 packets/s. Saturation
					// belongs in the measured netem benchmark, not a test
					// whose offered load depends on CI scheduling.
					tick := time.NewTicker(10 * time.Millisecond)
					defer tick.Stop()
					for _, packet := range payloads {
						select {
						case <-tick.C:
						case <-cancel:
							return
						}
						select {
						case peers[0].tun.Outbound <- packet:
						case <-cancel:
							return
						}
					}
				}()
				deadline := time.NewTimer(4 * time.Second)
				defer deadline.Stop()
				delivered := 0
			collect:
				for delivered < packets {
					select {
					case packet := <-peers[1].tun.Inbound:
						if bytes.Equal(packet, testIPv4Packet(peers[0].ipv4, peers[1].ipv4, 900, 0)) {
							continue // a warmup retry already in flight
						}
						key := string(packet)
						seen, known := expected[key]
						if !known {
							t.Fatal("received corrupted or unexpected inner packet")
						}
						if seen {
							t.Fatal("duplicate plaintext escaped WireGuard replay protection")
						}
						expected[key] = true
						delivered++
					case <-deadline.C:
						break collect
					}
				}
				if delivered < packets/3 {
					t.Fatalf("only %d/%d intact datagrams arrived", delivered, packets)
				}
				stats := peers[0].bind.Stats()
				t.Logf("fec=%s intact_unique=%d/%d outer_drops=%d fec_recovered=%d sender_queue_drops=%d expired=%d",
					fec, delivered, packets, path.dropped.Load(), peers[1].bind.Stats().FECRecovered,
					stats.QueueDrops, stats.SendQueueExpired)
				path.set(faultProfile{})
				probeImpaired(t, peers[0], peers[1], 1000, 5*time.Second)
				probeImpaired(t, peers[1], peers[0], 1001, 5*time.Second)
			})
		}
	}
}
