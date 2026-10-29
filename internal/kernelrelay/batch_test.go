package kernelrelay

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

type batchAction struct {
	n     int
	err   error
	short bool
}
type scriptedBatch struct {
	actions []batchAction
	calls   [][]byte
}

func (s *scriptedBatch) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	a := s.actions[0]
	s.actions = s.actions[1:]
	return a.n, a.err
}
func (s *scriptedBatch) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	if flags != 0 {
		panic("nonzero flags would bypass readiness polling")
	}
	ids := make([]byte, len(ms))
	for i := range ms {
		ids[i] = ms[i].Buffers[0][0]
	}
	s.calls = append(s.calls, ids)
	a := s.actions[0]
	s.actions = s.actions[1:]
	if a.n >= 0 && a.n <= len(ms) {
		for i := 0; i < a.n; i++ {
			ms[i].N = len(ms[i].Buffers[0])
			if a.short && i == a.n-1 {
				ms[i].N--
			}
		}
	}
	return a.n, a.err
}
func testMessages() []ipv4.Message {
	return []ipv4.Message{{Buffers: [][]byte{{1, 1, 1}}}, {Buffers: [][]byte{{2, 2, 2}}}, {Buffers: [][]byte{{3, 3, 3}}}}
}
func TestBatchWritePartialAndInterruptedPrefixes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		actions     []batchAction
		wantCalls   [][]byte
		wantBatches int
	}{
		{"partial then EINTR", []batchAction{{2, nil, false}, {0, os.NewSyscallError("sendmmsg", syscall.EINTR), false}, {1, nil, false}}, [][]byte{{1, 2, 3}, {3}, {3}}, 2},
		{"positive prefix and EINTR", []batchAction{{1, syscall.EINTR, false}, {2, nil, false}}, [][]byte{{1, 2, 3}, {2, 3}}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedBatch{actions: tc.actions}
			got, err := writeLocalBatch(s, testMessages())
			if err != nil {
				t.Fatal(err)
			}
			if got.packets != 3 || got.bytes != 9 || got.batches != tc.wantBatches {
				t.Fatalf("wrong progress: %+v", got)
			}
			if len(s.calls) != len(tc.wantCalls) {
				t.Fatal(s.calls)
			}
			for i := range s.calls {
				if !bytes.Equal(s.calls[i], tc.wantCalls[i]) {
					t.Fatalf("prefix replayed: %v", s.calls)
				}
			}
		})
	}
}
func TestBatchWriteFailuresDoNotSpinOrReplay(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action batchAction
		want   error
	}{
		{"no progress", batchAction{}, io.ErrNoProgress},
		{"short packet", batchAction{2, nil, true}, io.ErrShortWrite},
		{"unexpected EAGAIN", batchAction{0, syscall.EAGAIN, false}, syscall.EAGAIN},
		{"closed", batchAction{0, net.ErrClosed, false}, net.ErrClosed},
		{"invalid negative", batchAction{-1, nil, false}, nil},
		{"invalid oversized", batchAction{4, nil, false}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedBatch{actions: []batchAction{tc.action}}
			_, err := writeLocalBatch(s, testMessages())
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if len(s.calls) != 1 {
				t.Fatal("failure retried without a readiness contract")
			}
		})
	}
	s := &scriptedBatch{actions: []batchAction{{1, nil, false}, {0, net.ErrClosed, false}}}
	got, err := writeLocalBatch(s, testMessages())
	if !errors.Is(err, net.ErrClosed) || got.packets != 1 || got.bytes != 3 {
		t.Fatal(got, err)
	}
}
func TestBatchReadRetriesOnlyInterruptedEmptyRead(t *testing.T) {
	s := &scriptedBatch{actions: []batchAction{{0, syscall.EINTR, false}, {2, nil, false}}}
	if n, err := readLocalBatch(s, testMessages()); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	for _, a := range []batchAction{{-1, nil, false}, {4, nil, false}, {0, nil, false}, {0, net.ErrClosed, false}, {0, syscall.EAGAIN, false}} {
		s := &scriptedBatch{actions: []batchAction{a}}
		if _, err := readLocalBatch(s, testMessages()); err == nil {
			t.Fatal("invalid read accepted")
		}
	}
}
func TestBatchPacketBoundsAndSources(t *testing.T) {
	expected := netip.MustParseAddrPort("127.0.0.1:12345")
	packet := make([]byte, 65536)
	packet[0] = 4
	base := ipv4.Message{Buffers: [][]byte{packet}, N: 32, Addr: net.UDPAddrFromAddrPort(expected)}
	if _, ok := localPacket(base, expected); !ok {
		t.Fatal("valid packet rejected")
	}
	for name, change := range map[string]func(*ipv4.Message){
		"negative length":       func(m *ipv4.Message) { m.N = -1 },
		"over buffer":           func(m *ipv4.Message) { m.N = 65537 },
		"over UDP limit":        func(m *ipv4.Message) { m.N = 65508 },
		"truncated payload":     func(m *ipv4.Message) { m.Flags = syscall.MSG_TRUNC },
		"truncated control":     func(m *ipv4.Message) { m.Flags = syscall.MSG_CTRUNC },
		"missing source":        func(m *ipv4.Message) { m.Addr = nil },
		"different source port": func(m *ipv4.Message) { m.Addr = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:12346")) },
		"different source IP":   func(m *ipv4.Message) { m.Addr = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.2:12345")) },
		"missing buffer":        func(m *ipv4.Message) { m.Buffers = nil },
		"unexpected vector":     func(m *ipv4.Message) { m.Buffers = append(m.Buffers, []byte{1}) },
		"zero payload":          func(m *ipv4.Message) { m.N = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			change(&m)
			if _, ok := localPacket(m, expected); ok {
				t.Fatal("unsafe datagram accepted")
			}
		})
	}
	base.N = 65507
	if _, ok := localPacket(base, expected); !ok {
		t.Fatal("maximum whole IPv4 datagram rejected")
	}
}
func connectedBatchFixture(t *testing.T) (*net.UDPConn, *net.UDPConn, *ipv4.PacketConn) {
	t.Helper()
	server := udpSocket(t)
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return server, client, ipv4.NewPacketConn(client)
}
func TestNativeBatchDrainsReadyPacketsAndPreservesBoundaries(t *testing.T) {
	server, client, batch := connectedBatchFixture(t)
	for i := 0; i < 8; i++ {
		p := bytes.Repeat([]byte{byte(i)}, 32+i)
		if _, err := server.WriteToUDPAddrPort(p, client.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			t.Fatal(err)
		}
	}
	ms := make([]ipv4.Message, 32)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 65536)}
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	n, err := readLocalBatch(batch, ms)
	if err != nil || n != 8 {
		t.Fatalf("ready burst not batched: n=%d err=%v", n, err)
	}
	for i := 0; i < n; i++ {
		if !bytes.Equal(ms[i].Buffers[0][:ms[i].N], bytes.Repeat([]byte{byte(i)}, 32+i)) {
			t.Fatal("boundary or payload changed")
		}
	}
	// One ready packet returns without waiting for the unused 31 slots.
	if _, err := server.WriteToUDPAddrPort([]byte{99}, client.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}
	n, err = readLocalBatch(batch, ms)
	if err != nil || n != 1 {
		t.Fatal("waited for a full batch", n, err)
	}
}
func TestNativeBatchEAGAINParksAndCloseCancels(t *testing.T) {
	server, client, batch := connectedBatchFixture(t)
	ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 65536)}}}
	done := make(chan error, 1)
	go func() { _, err := readLocalBatch(batch, ms); done <- err }()
	select {
	case err := <-done:
		t.Fatal("empty socket did not park", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := server.WriteToUDPAddrPort([]byte{4, 0, 0, 0}, client.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ready socket did not wake")
	}
	go func() { _, err := readLocalBatch(batch, ms); done <- err }()
	client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel netpoll")
	}
}
func TestNativeBatchWriteUsesConnectedDestination(t *testing.T) {
	server, _, batch := connectedBatchFixture(t)
	ms := testMessages()
	result, err := writeLocalBatch(batch, ms)
	if err != nil || result.packets != 3 || result.batches != 1 {
		t.Fatal(result, err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	for i := byte(1); i <= 3; i++ {
		n, _, err := server.ReadFromUDPAddrPort(b)
		if err != nil || !bytes.Equal(b[:n], []byte{i, i, i}) {
			t.Fatal("write boundary changed", n, err)
		}
	}
}
func BenchmarkEndpointAdmission(b *testing.B) {
	address := netip.MustParseAddrPort("127.0.0.1:34567")
	r := &Relay{cfg: Config{PeerQUICEndpoint: address}}
	ep := testEndpoint{address, 1}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !r.acceptEndpoint(ep) {
			b.Fatal("rejected")
		}
	}
}
