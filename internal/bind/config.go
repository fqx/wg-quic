package armorbind

import (
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/RC-CHN/wg-quic/internal/transport/fec"
	"github.com/RC-CHN/wg-quic/internal/transport/obfs"
)

type Config struct {
	QueueSize int
	// Admission limits apply before allocating session queues or FEC state.
	MaxSessions                  int
	MaxInboundSessions           int
	MaxPendingInboundSessions    int
	InboundAuthenticationTimeout time.Duration
	// DatagramReceiveQueueCapacity tunes the quic-go DATAGRAM receive
	// queue depth; zero keeps the fork default (128). Tune it against the
	// quic_datagram_rcv_queue_drops and high-water counters, not by
	// guesswork.
	DatagramReceiveQueueCapacity int
	// QueueDropEventInterval bounds how often a queue-full drop may build a
	// telemetry snapshot and a session event. The queueDrops counter still
	// counts every rejected packet; the interval only rate-limits the
	// per-drop diagnostic work, so diagnostic output cannot grow with the
	// packet rate.
	QueueDropEventInterval time.Duration
	HandshakeTimeout       time.Duration
	MaxIdleTimeout         time.Duration
	KeepAlivePeriod        time.Duration
	ReconnectMin           time.Duration
	ReconnectMax           time.Duration
	ReconnectStable        time.Duration
	ReconnectJitter        func(time.Duration) time.Duration
	CongestionMode         string
	FECMode                string
	FECDataShards          int
	FECInterleave          int
	FECFlushDeadline       time.Duration
	ObfsMode               string
	ObfsKeys               []obfs.Key
	Eventf                 func(format string, args ...any)
	Debugf                 func(format string, args ...any)
}

func DefaultConfig() Config {
	return Config{
		QueueSize:                    1024,
		MaxSessions:                  1024,
		MaxInboundSessions:           256,
		MaxPendingInboundSessions:    32,
		InboundAuthenticationTimeout: 10 * time.Second,
		QueueDropEventInterval:       time.Second,
		HandshakeTimeout:             4 * time.Second,
		MaxIdleTimeout:               15 * time.Second,
		KeepAlivePeriod:              5 * time.Second,
		ReconnectMin:                 250 * time.Millisecond,
		ReconnectMax:                 30 * time.Second,
		ReconnectStable:              10 * time.Second,
		ReconnectJitter: func(value time.Duration) time.Duration {
			return value * time.Duration(900+rand.IntN(201)) / 1000
		},
		CongestionMode:   "model",
		FECMode:          "auto",
		FECDataShards:    fec.MaxDataShards,
		FECInterleave:    1,
		FECFlushDeadline: 2 * time.Millisecond,
		ObfsMode:         "none",
	}
}

func New(cfg Config) *Bind {
	defaults := DefaultConfig()
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaults.MaxSessions
	}
	if cfg.MaxInboundSessions <= 0 {
		cfg.MaxInboundSessions = defaults.MaxInboundSessions
	}
	if cfg.MaxPendingInboundSessions <= 0 {
		cfg.MaxPendingInboundSessions = defaults.MaxPendingInboundSessions
	}
	if cfg.InboundAuthenticationTimeout <= 0 {
		cfg.InboundAuthenticationTimeout = defaults.InboundAuthenticationTimeout
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaults.QueueSize
	}
	if cfg.QueueDropEventInterval <= 0 {
		cfg.QueueDropEventInterval = defaults.QueueDropEventInterval
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaults.HandshakeTimeout
	}
	if cfg.MaxIdleTimeout <= 0 {
		cfg.MaxIdleTimeout = defaults.MaxIdleTimeout
	}
	if cfg.KeepAlivePeriod <= 0 {
		cfg.KeepAlivePeriod = defaults.KeepAlivePeriod
	}
	if cfg.ReconnectMin <= 0 {
		cfg.ReconnectMin = defaults.ReconnectMin
	}
	if cfg.ReconnectMax < cfg.ReconnectMin {
		cfg.ReconnectMax = max(cfg.ReconnectMin, defaults.ReconnectMax)
	}
	if cfg.ReconnectStable <= 0 {
		cfg.ReconnectStable = defaults.ReconnectStable
	}
	if cfg.ReconnectJitter == nil {
		cfg.ReconnectJitter = defaults.ReconnectJitter
	}
	if cfg.CongestionMode == "" || cfg.CongestionMode == "auto" {
		cfg.CongestionMode = defaults.CongestionMode
	}
	if cfg.FECMode == "" {
		cfg.FECMode = defaults.FECMode
	}
	if cfg.FECDataShards <= 0 {
		cfg.FECDataShards = defaults.FECDataShards
	}
	if cfg.FECInterleave <= 0 {
		cfg.FECInterleave = defaults.FECInterleave
	}
	if cfg.FECFlushDeadline <= 0 {
		cfg.FECFlushDeadline = defaults.FECFlushDeadline
	}
	if cfg.ObfsMode == "" {
		cfg.ObfsMode = defaults.ObfsMode
	}
	cfg.ObfsKeys = append([]obfs.Key(nil), cfg.ObfsKeys...)
	return &Bind{
		cfg: cfg, obfsResolved: make(map[netip.AddrPort]obfs.Key),
		obfsDynamic:  make(map[netip.AddrPort]endpointKeyLease),
		obfsReceive:  make(map[obfs.Key]receiveKeyLease),
		fecPolicies:  make(map[netip.AddrPort]endpointFECPolicyLease),
		replacements: make(map[uint64]uint64),
		events:       newSessionEventLog(),
	}
}
