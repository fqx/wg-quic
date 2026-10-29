package kernelrelay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/sys/unix"
)

// LinuxObserver reads the kernel WireGuard generic-netlink UAPI. This small
// experiment-specific reader accepts exactly one peer; it never sends SET.
// See include/uapi/linux/wireguard.h. A GET dump necessarily contains secret
// attributes; they are skipped without decoding and the receive buffer is
// cleared on every path. Do not use this against a production interface.
type LinuxObserver struct {
	Interface     string
	PeerPublicKey [32]byte
}

type attribute struct {
	kind  uint16
	value []byte
}

func attributes(data []byte) ([]attribute, error) {
	var result []attribute
	for len(data) != 0 {
		if len(data) < 4 {
			return nil, errors.New("short netlink attribute header")
		}
		n := int(binary.NativeEndian.Uint16(data[:2]))
		if n < 4 || n > len(data) {
			return nil, errors.New("invalid netlink attribute length")
		}
		result = append(result, attribute{binary.NativeEndian.Uint16(data[2:4]) & 0x3fff, data[4:n]})
		aligned := (n + 3) &^ 3
		if aligned > len(data) {
			return nil, errors.New("short netlink attribute padding")
		}
		data = data[aligned:]
	}
	return result, nil
}

func appendAttribute(data []byte, kind uint16, value []byte) []byte {
	n := 4 + len(value)
	start := len(data)
	data = append(data, make([]byte, (n+3)&^3)...)
	binary.NativeEndian.PutUint16(data[start:], uint16(n))
	binary.NativeEndian.PutUint16(data[start+2:], kind)
	copy(data[start+4:], value)
	return data
}

func (o LinuxObserver) Snapshot() (PeerSnapshot, error) {
	var snapshot PeerSnapshot
	if o.Interface == "" || len(o.Interface) >= unix.IFNAMSIZ || strings.IndexByte(o.Interface, 0) >= 0 || o.PeerPublicKey == ([32]byte{}) {
		return snapshot, errors.New("invalid experiment WireGuard interface or peer")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_GENERIC)
	if err != nil {
		return snapshot, err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return snapshot, err
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return snapshot, err
	}
	var family uint16
	request := appendAttribute([]byte{unix.CTRL_CMD_GETFAMILY, 1, 0, 0}, 2, []byte("wireguard\x00"))
	err = netlinkRequest(fd, unix.GENL_ID_CTRL, unix.NLM_F_REQUEST, 1, request, func(body []byte) error {
		if len(body) < 4 {
			return errors.New("short generic netlink family reply")
		}
		attrs, err := attributes(body[4:])
		if err != nil {
			return err
		}
		for _, a := range attrs {
			if a.kind == 1 && len(a.value) == 2 {
				family = binary.NativeEndian.Uint16(a.value)
			}
		}
		return nil
	})
	if err != nil {
		return snapshot, fmt.Errorf("WireGuard netlink family: %w", err)
	}
	if family < unix.GENL_MIN_ID {
		return snapshot, errors.New("WireGuard netlink family missing")
	}
	parser := deviceDump{expectedInterface: o.Interface, expectedPeer: o.PeerPublicKey}
	request = appendAttribute([]byte{0, 1, 0, 0}, 2, append([]byte(o.Interface), 0))
	err = netlinkRequest(fd, family, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, 2, request, parser.consume)
	if err != nil {
		return snapshot, err
	}
	if !parser.haveInterface || !parser.havePeer || !parser.havePort || !parser.haveRX {
		return snapshot, errors.New("incomplete single-peer WireGuard dump")
	}
	return parser.snapshot, nil
}

func netlinkRequest(fd int, family, flags uint16, sequence uint32, body []byte, consume func([]byte) error) error {
	request := make([]byte, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], family)
	binary.NativeEndian.PutUint16(request[6:], flags)
	binary.NativeEndian.PutUint32(request[8:], sequence)
	copy(request[unix.NLMSG_HDRLEN:], body)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, 65536)
	defer clear(buffer)
	for received := 0; received < 1<<20; {
		n, _, recvFlags, from, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err != nil {
			return err
		}
		received += n
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || recvFlags&unix.MSG_TRUNC != 0 {
			return errors.New("untrusted or truncated netlink reply")
		}
		data := buffer[:n]
		for len(data) != 0 {
			if len(data) < unix.NLMSG_HDRLEN {
				return errors.New("short netlink message")
			}
			length := int(binary.NativeEndian.Uint32(data))
			if length < unix.NLMSG_HDRLEN || length > len(data) {
				return errors.New("invalid netlink message length")
			}
			kind := binary.NativeEndian.Uint16(data[4:])
			messageFlags := binary.NativeEndian.Uint16(data[6:])
			if binary.NativeEndian.Uint32(data[8:]) != sequence {
				return errors.New("netlink reply sequence mismatch")
			}
			if messageFlags&unix.NLM_F_DUMP_INTR != 0 {
				return errors.New("interrupted WireGuard netlink dump")
			}
			payload := data[unix.NLMSG_HDRLEN:length]
			switch kind {
			case unix.NLMSG_ERROR, unix.NLMSG_DONE:
				if len(payload) < 4 {
					return errors.New("missing netlink status")
				}
				status := int32(binary.NativeEndian.Uint32(payload))
				if status != 0 {
					if status > 0 {
						return errors.New("invalid netlink errno")
					}
					return unix.Errno(-status)
				}
				if kind == unix.NLMSG_DONE || flags&unix.NLM_F_DUMP == 0 {
					return nil
				}
			default:
				if kind != family {
					return errors.New("unexpected netlink reply family")
				}
				if err := consume(payload); err != nil {
					return err
				}
				if messageFlags&unix.NLM_F_MULTI == 0 {
					if flags&unix.NLM_F_DUMP != 0 {
						return errors.New("incomplete non-multipart WireGuard dump")
					}
					return nil
				}
			}
			aligned := (length + 3) &^ 3
			if aligned > len(data) {
				return errors.New("short netlink message padding")
			}
			data = data[aligned:]
		}
		clear(buffer)
	}
	return errors.New("WireGuard netlink dump exceeds experiment bound")
}

type deviceDump struct {
	expectedInterface                         string
	expectedPeer                              [32]byte
	snapshot                                  PeerSnapshot
	haveInterface, havePeer, havePort, haveRX bool
}

func (d *deviceDump) consume(body []byte) error {
	if len(body) < 4 || body[0] != 0 || body[1] != 1 {
		return errors.New("unexpected WireGuard generic netlink message")
	}
	attrs, err := attributes(body[4:])
	if err != nil {
		return err
	}
	for _, a := range attrs {
		switch a.kind {
		case 2:
			if string(a.value) != d.expectedInterface+"\x00" {
				return errors.New("WireGuard interface identity mismatch")
			}
			d.haveInterface = true
		case 6:
			if len(a.value) != 2 {
				return errors.New("invalid WireGuard listen port")
			}
			d.snapshot.ListenPort = binary.NativeEndian.Uint16(a.value)
			d.havePort = true
		case 8:
			peers, err := attributes(a.value)
			if err != nil {
				return err
			}
			for _, peer := range peers {
				if err := d.peer(peer.value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (d *deviceDump) peer(data []byte) error {
	attrs, err := attributes(data)
	if err != nil {
		return err
	}
	var key [32]byte
	haveKey := false
	for _, a := range attrs {
		if a.kind == 1 {
			if haveKey || len(a.value) != 32 {
				return errors.New("invalid WireGuard peer key")
			}
			copy(key[:], a.value)
			haveKey = true
		}
	}
	if !haveKey || key != d.expectedPeer {
		return errors.New("experiment requires exactly one specified kernel peer")
	}
	continuation := d.havePeer
	d.havePeer = true
	d.snapshot.PublicKey = key
	for _, a := range attrs {
		// A repeated peer may contain only key and AllowedIPs fragments.
		if continuation && a.kind != 1 && a.kind != 9 {
			return errors.New("duplicate kernel peer state")
		}
		switch a.kind {
		case 4:
			endpoint, err := parseEndpoint(a.value)
			if err != nil {
				return err
			}
			d.snapshot.Endpoint = endpoint
		case 6:
			if len(a.value) != 16 {
				return errors.New("invalid WireGuard handshake time")
			}
			d.snapshot.HandshakeSec = int64(binary.NativeEndian.Uint64(a.value))
			d.snapshot.HandshakeNsec = int64(binary.NativeEndian.Uint64(a.value[8:]))
			if d.snapshot.HandshakeSec < 0 || d.snapshot.HandshakeNsec < 0 || d.snapshot.HandshakeNsec >= 1e9 {
				return errors.New("invalid WireGuard handshake timestamp")
			}
		case 7:
			if len(a.value) != 8 || d.haveRX {
				return errors.New("invalid or repeated WireGuard RX counter")
			}
			d.snapshot.RxBytes = binary.NativeEndian.Uint64(a.value)
			d.haveRX = true
		case 8:
			if len(a.value) != 8 {
				return errors.New("invalid WireGuard TX counter")
			}
			d.snapshot.TxBytes = binary.NativeEndian.Uint64(a.value)
		}
	}
	return nil
}

func parseEndpoint(data []byte) (netip.AddrPort, error) {
	if len(data) < 4 {
		return netip.AddrPort{}, errors.New("short WireGuard endpoint")
	}
	port := binary.BigEndian.Uint16(data[2:4])
	switch binary.NativeEndian.Uint16(data) {
	case unix.AF_INET:
		if len(data) != 16 {
			break
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[4:8])), port), nil
	case unix.AF_INET6:
		if len(data) != 28 {
			break
		}
		// The relay permits only IPv4 loopback locally; parsing IPv6 here
		// ensures unrelated configured state is rejected, never misread.
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(data[8:24])), port), nil
	}
	return netip.AddrPort{}, errors.New("invalid WireGuard endpoint sockaddr")
}
