package kernelrelay

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func native64(v uint64) []byte { b := make([]byte, 8); binary.NativeEndian.PutUint64(b, v); return b }
func native16(v uint16) []byte { b := make([]byte, 2); binary.NativeEndian.PutUint16(b, v); return b }
func sockaddr4(port uint16) []byte {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint16(b, unix.AF_INET)
	binary.BigEndian.PutUint16(b[2:], port)
	copy(b[4:], []byte{127, 0, 0, 1})
	return b
}
func testPeer(key [32]byte) []byte {
	b := appendAttribute(nil, 1, key[:])
	b = appendAttribute(b, 2, make([]byte, 32)) // PSK is ignored.
	b = appendAttribute(b, 4, sockaddr4(12345))
	b = appendAttribute(b, 6, append(native64(123), native64(456)...))
	b = appendAttribute(b, 7, native64(148))
	b = appendAttribute(b, 8, native64(92))
	return b
}
func dumpMessage(peer []byte) []byte {
	b := appendAttribute([]byte{0, 1, 0, 0}, 2, []byte("wg-test\x00"))
	b = appendAttribute(b, 3, make([]byte, 32)) // private key is ignored.
	b = appendAttribute(b, 6, native16(51820))
	b = appendAttribute(b, 8|unix.NLA_F_NESTED, appendAttribute(nil, unix.NLA_F_NESTED, peer))
	return b
}

func TestKernelDumpOnePeerAndMultipartAllowedIPs(t *testing.T) {
	key := [32]byte{1}
	parser := deviceDump{expectedInterface: "wg-test", expectedPeer: key}
	if err := parser.consume(dumpMessage(testPeer(key))); err != nil {
		t.Fatal(err)
	}
	want := PeerSnapshot{PublicKey: key, Endpoint: netip.MustParseAddrPort("127.0.0.1:12345"), ListenPort: 51820, RxBytes: 148, TxBytes: 92, HandshakeSec: 123, HandshakeNsec: 456}
	if parser.snapshot != want || !parser.haveRX || !parser.havePeer || !parser.havePort {
		t.Fatalf("snapshot = %+v", parser.snapshot)
	}
	continuation := appendAttribute(nil, 1, key[:])
	continuation = appendAttribute(continuation, 9|unix.NLA_F_NESTED, nil)
	if err := parser.consume(dumpMessage(continuation)); err != nil {
		t.Fatal(err)
	}
	if parser.snapshot != want {
		t.Fatal("multipart continuation changed state")
	}
	if err := parser.consume(dumpMessage(testPeer(key))); err == nil {
		t.Fatal("repeated peer core state accepted")
	}
}

func TestKernelDumpRejectsAmbiguousMalformedState(t *testing.T) {
	key := [32]byte{1}
	for name, body := range map[string][]byte{
		"different peer":      dumpMessage(testPeer([32]byte{2})),
		"short peer key":      dumpMessage(appendAttribute(nil, 1, []byte{1})),
		"missing peer key":    dumpMessage(appendAttribute(nil, 7, native64(100))),
		"bad RX length":       dumpMessage(appendAttribute(appendAttribute(nil, 1, key[:]), 7, []byte{1})),
		"bad endpoint":        dumpMessage(appendAttribute(appendAttribute(nil, 1, key[:]), 4, []byte{1, 2, 3})),
		"wrong command":       {1, 1, 0, 0},
		"truncated attribute": {0, 1, 0, 0, 0xff, 0xff, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			parser := deviceDump{expectedInterface: "wg-test", expectedPeer: key}
			if err := parser.consume(body); err == nil {
				t.Fatal("ambiguous state accepted")
			}
		})
	}
	parser := deviceDump{expectedInterface: "different", expectedPeer: key}
	if err := parser.consume(dumpMessage(testPeer(key))); err == nil {
		t.Fatal("wrong interface accepted")
	}
	parser = deviceDump{expectedInterface: "wg-test", expectedPeer: key}
	if err := parser.consume(dumpMessage(testPeer(key))); err != nil {
		t.Fatal(err)
	}
	if err := parser.consume(dumpMessage(testPeer([32]byte{2}))); err == nil {
		t.Fatal("second peer accepted")
	}
}

func TestNetlinkAttributeBounds(t *testing.T) {
	for _, data := range [][]byte{{0}, {3, 0, 1, 0}, {9, 0, 1, 0, 1}, {5, 0, 1, 0, 1}} {
		if _, err := attributes(data); err == nil {
			t.Fatalf("accepted %x", data)
		}
	}
	encoded := appendAttribute(nil, 17|unix.NLA_F_NESTED, []byte{1, 2, 3})
	attrs, err := attributes(encoded)
	if err != nil || len(attrs) != 1 || attrs[0].kind != 17 {
		t.Fatalf("attrs=%v err=%v", attrs, err)
	}
}
