package armorbind

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/RC-CHN/wg-quic/internal/telemetry"
	"github.com/RC-CHN/wg-quic/third_party/wireguard-go/conn"
)

func BenchmarkSessionEventHistory(b *testing.B) {
	bind := New(DefaultConfig())
	now := time.Now()
	for range maxSessionEvents {
		bind.recordSessionEventAt(1, 1, telemetry.SessionEventLoss, "", now, nil, nil)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		bind.recordSessionEventAt(1, 1, telemetry.SessionEventLoss, "", now, nil, nil)
	}
}

func BenchmarkSessionLifecycle(b *testing.B) {
	for _, count := range []int{1, 32, 256, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			cfg := DefaultConfig()
			owner := New(cfg)
			state := &runState{
				ctx: b.Context(), cfg: cfg,
				sessions: make(map[uint64]*session), endpoints: make(map[netip.AddrPort]*Endpoint),
			}
			owner.state = state
			endpoints := make([]*Endpoint, count)
			for i := range endpoints {
				endpoints[i] = &Endpoint{owner: owner, addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(i+1))}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for _, ep := range endpoints {
					state.mu.Lock()
					ep.session = owner.newSessionLocked(state, ep, false)
					state.mu.Unlock()
				}
				for _, ep := range endpoints {
					ep.session.close()
				}
			}
		})
	}
}

func TestReconnectResumesAfterAdmissionPressure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSessions = 1
	cfg.ReconnectMin = 10 * time.Millisecond
	cfg.ReconnectMax = 20 * time.Millisecond
	cfg.ReconnectJitter = func(d time.Duration) time.Duration { return d }
	a, b := New(cfg), New(cfg)
	if _, _, err := a.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	_, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	endpoint, err := a.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
	if err != nil {
		t.Fatal(err)
	}
	ep := endpoint.(*Endpoint)
	ep.mu.Lock()
	ep.activated = true
	ep.mu.Unlock()
	occupied := inboundFixture(a, a.state)
	a.scheduleEndpointReconnect(a.state, ep, true)
	waitForCondition(t, "admission pressure reached", func() bool {
		return a.stats.sessionAdmissionRejected.Load() > 0
	})
	occupied.close()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if a.EndpointSessionState(ep.addr) == EndpointSessionEstablished {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("maintained endpoint never resumed after capacity became available without new application traffic")
		}
	}
}

func TestSessionEventHistoryMultipleWraps(t *testing.T) {
	b := New(DefaultConfig())
	for i := 0; i < maxSessionEvents*3+17; i++ {
		b.recordSessionEventAt(uint64(i), 1, telemetry.SessionEventLoss, "", time.Now(), nil, nil)
	}
	var cursor uint64
	var count int
	for {
		page, err := b.SessionEvents(b.ObservationID(), cursor, 127)
		if err != nil {
			t.Fatal(err)
		}
		if page.EventsDroppedTotal != 2*maxSessionEvents+17 {
			t.Fatalf("dropped = %d", page.EventsDroppedTotal)
		}
		if len(page.Events) == 0 {
			break
		}
		for _, event := range page.Events {
			if count > 0 && event.EventSequence != cursor+1 {
				t.Fatalf("cursor gap: %d -> %d", cursor, event.EventSequence)
			}
			cursor = event.EventSequence
			count++
		}
	}
	if count != maxSessionEvents {
		t.Fatalf("read %d events", count)
	}
}

func TestReconnectConfigurationBounds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReconnectMin = time.Minute
	cfg.ReconnectMax = 0
	b := New(cfg)
	if b.cfg.ReconnectMax < b.cfg.ReconnectMin {
		t.Fatal("normalization left maximum backoff below the minimum")
	}
	for _, exponent := range []uint32{0, 1, 10, 1000} {
		delay := reconnectBackoff(b.cfg.ReconnectMin, b.cfg.ReconnectMax, exponent)
		if delay < b.cfg.ReconnectMin || delay > b.cfg.ReconnectMax {
			t.Fatalf("backoff outside normalized limits: %s", delay)
		}
	}
}

// Stress the real QUIC listener, cold concurrent dials, routing and teardown.
// Payloads are opaque bind datagrams, so this measures transport connections,
// not authenticated WireGuard peers. Raise only the pending-authentication cap
// for the controlled fixture; production defaults remain unchanged.
func TestTransportConnectionScale(t *testing.T) {
	for _, count := range []int{1, 32, 128} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MaxPendingInboundSessions = count
			server := New(cfg)
			receive, port, err := server.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
			clients := make([]*Bind, count)
			receivers := make([]conn.ReceiveFunc, count)
			endpoints := make([]conn.Endpoint, count)
			for i := range clients {
				client := New(cfg)
				r, _, err := client.Open(0)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				clients[i], receivers[i] = client, r[0]
				endpoints[i], err = client.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
				if err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, count+1)
			go func() {
				buf := make([]byte, 2048)
				sizes := make([]int, 1)
				eps := make([]conn.Endpoint, 1)
				for range count {
					if _, err := receive[0]([][]byte{buf}, sizes, eps); err != nil {
						done <- err
						return
					}
					if err := server.Send([][]byte{buf[:sizes[0]]}, eps[0]); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			start := time.Now()
			for i, client := range clients {
				go func() {
					payload := []byte(fmt.Sprintf("connection-%d", i))
					if err := client.Send([][]byte{payload}, endpoints[i]); err != nil {
						done <- err
						return
					}
					buf := make([]byte, 2048)
					sizes := make([]int, 1)
					_, err := receivers[i]([][]byte{buf}, sizes, make([]conn.Endpoint, 1))
					if err == nil && !bytes.Equal(buf[:sizes[0]], payload) {
						err = fmt.Errorf("connection %d received the wrong payload", i)
					}
					done <- err
				}()
			}
			deadline := time.NewTimer(8 * time.Second)
			defer deadline.Stop()
			for range count + 1 {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-deadline.C:
					t.Fatal("concurrent cold connections did not deliver within the deadline")
				}
			}
			t.Logf("connections=%d cold_bidirectional_delivery=%s", count, time.Since(start))
			if active := server.stats.activeSessions.Load(); active != uint64(count) {
				t.Fatalf("active=%d want=%d", active, count)
			}
			start = time.Now()
			var wg sync.WaitGroup
			for _, client := range clients {
				wg.Go(func() { client.Close() })
			}
			wg.Wait()
			server.Close()
			if server.stats.activeSessions.Load() != 0 {
				t.Fatal("server leaked sessions")
			}
			t.Logf("connections=%d shutdown=%s", count, time.Since(start))
		})
	}
}
