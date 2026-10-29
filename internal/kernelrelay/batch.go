package kernelrelay

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv4"
)

const localBatchSize = 32

type batchSocket interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

type batchWriteResult struct {
	packets, bytes, batches, multiPackets, maxBatch int
}

// flags=0 is intentional. x/net uses Go's nonblocking RawConn: EAGAIN
// parks in netpoll until the first packet / writable socket, then recvmmsg
// drains only ready datagrams. It never waits for a batch to fill.
func readLocalBatch(socket batchSocket, messages []ipv4.Message) (int, error) {
	for {
		n, err := socket.ReadBatch(messages, 0)
		if n < 0 || n > len(messages) {
			return 0, errors.New("invalid UDP batch read count")
		}
		if n == 0 && errors.Is(err, syscall.EINTR) {
			continue
		}
		// An unpack error can leave stale per-message N/Addr fields. Never expose
		// a supposedly readable prefix unless the batch API completed successfully.
		if n > 0 && err != nil {
			return 0, err
		}
		if n == 0 && err == nil {
			return 0, io.ErrNoProgress
		}
		return n, err
	}
}

// A positive prefix is never replayed, including when an error accompanies it.
// EAGAIN is handled inside x/net's RawConn.Write(flags=0). If an adapter
// unexpectedly exposes it, fail closed rather than busy-spinning.
func writeLocalBatch(socket batchSocket, messages []ipv4.Message) (batchWriteResult, error) {
	var result batchWriteResult
	for len(messages) > 0 {
		n, err := socket.WriteBatch(messages, 0)
		if n < 0 || n > len(messages) {
			return result, errors.New("invalid UDP batch write count")
		}
		for i := 0; i < n; i++ {
			size := 0
			for _, b := range messages[i].Buffers {
				size += len(b)
			}
			if messages[i].N != size {
				return result, io.ErrShortWrite
			}
			result.packets++
			result.bytes += size
		}
		if n > 0 {
			result.batches++
			if n > 1 {
				result.multiPackets += n
			}
			if n > result.maxBatch {
				result.maxBatch = n
			}
			messages = messages[n:]
		}
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return result, err
		}
		if n == 0 {
			return result, io.ErrNoProgress
		}
	}
	return result, nil
}

func localPacket(message ipv4.Message, expected netip.AddrPort) ([]byte, bool) {
	if len(message.Buffers) != 1 || message.N < 0 || message.N > len(message.Buffers[0]) || truncatedMessage(message.Flags) {
		return nil, false
	}
	source, ok := message.Addr.(*net.UDPAddr)
	if !ok || source == nil {
		return nil, false
	}
	addr := source.AddrPort()
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	if addr != expected {
		return nil, false
	}
	packet := message.Buffers[0][:message.N]
	return packet, validDatagram(packet)
}

func recordMaximum(counter *atomic.Uint64, value uint64) {
	for old := counter.Load(); value > old; old = counter.Load() {
		if counter.CompareAndSwap(old, value) {
			return
		}
	}
}
