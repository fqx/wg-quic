package armorbind

import (
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/RC-CHN/wg-quic/internal/telemetry"
	quiccarrier "github.com/RC-CHN/wg-quic/internal/transport/quic"
)

type bindStats struct {
	sessionAdmissionRejected atomic.Uint64
	authenticationTimeouts   atomic.Uint64
	wgTxPackets              atomic.Uint64
	wgTxBytes                atomic.Uint64
	wgRxPackets              atomic.Uint64
	wgRxBytes                atomic.Uint64
	wireTxPackets            atomic.Uint64
	wireTxBytes              atomic.Uint64
	wireRxPackets            atomic.Uint64
	wireRxBytes              atomic.Uint64
	queueDrops               atomic.Uint64
	sendQueueExpired         atomic.Uint64
	sendDelayMaxUs           atomic.Uint64
	fecDataTx                atomic.Uint64
	fecParityTx              atomic.Uint64
	fecRawLost               atomic.Uint64
	fecRecovered             atomic.Uint64
	fecUnrecovered           atomic.Uint64
	activeSessions           atomic.Uint64
}

type sessionCounters struct {
	wgTxPackets      atomic.Uint64
	wgTxBytes        atomic.Uint64
	wgRxPackets      atomic.Uint64
	wgRxBytes        atomic.Uint64
	wireTxPackets    atomic.Uint64
	wireTxBytes      atomic.Uint64
	wireRxPackets    atomic.Uint64
	wireRxBytes      atomic.Uint64
	queueDrops       atomic.Uint64
	sendQueueExpired atomic.Uint64
	fecDataTx        atomic.Uint64
	fecParityTx      atomic.Uint64
	fecRawLost       atomic.Uint64
	fecRecovered     atomic.Uint64
	fecUnrecovered   atomic.Uint64
}

func (b *Bind) Stats() telemetry.Stats {
	stats := telemetry.Stats{
		WGTxPackets: b.stats.wgTxPackets.Load(), WGTxBytes: b.stats.wgTxBytes.Load(),
		WGRxPackets: b.stats.wgRxPackets.Load(), WGRxBytes: b.stats.wgRxBytes.Load(),
		WireTxPackets: b.stats.wireTxPackets.Load(), WireTxBytes: b.stats.wireTxBytes.Load(),
		WireRxPackets: b.stats.wireRxPackets.Load(), WireRxBytes: b.stats.wireRxBytes.Load(),
		SendQueueExpired:    b.stats.sendQueueExpired.Load(),
		SendQueueDelayMaxUs: b.stats.sendDelayMaxUs.Load(),
		QueueDrops:          b.stats.queueDrops.Load(), FECDataTx: b.stats.fecDataTx.Load(),
		FECParityTx: b.stats.fecParityTx.Load(), FECRawLost: b.stats.fecRawLost.Load(),
		FECRecovered: b.stats.fecRecovered.Load(), FECUnrecovered: b.stats.fecUnrecovered.Load(),
		ActiveSessions:           b.stats.activeSessions.Load(),
		SessionAdmissionRejected: b.stats.sessionAdmissionRejected.Load(),
		AuthenticationTimeouts:   b.stats.authenticationTimeouts.Load(),
	}
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	if state != nil {
		overflow := state.carrier.ReceiveQueueOverflowStats()
		stats.ReceiveQueueOverflow = b.observeReceiveQueueOverflow(state.carrier, overflow)
	} else {
		stats.ReceiveQueueOverflow = telemetry.ReceiveQueueOverflowObservation{
			Source: "unavailable", Platform: runtime.GOOS,
		}
	}
	b.addQUICStats(&stats)
	return stats
}

func (b *Bind) observeReceiveQueueOverflow(
	carrier *quiccarrier.Carrier,
	observation quiccarrier.ReceiveQueueOverflowStats,
) telemetry.ReceiveQueueOverflowObservation {
	result := telemetry.ReceiveQueueOverflowObservation{
		Supported: observation.Supported, Source: observation.Source,
		Platform: runtime.GOOS, Packets: observation.Packets,
	}
	if !observation.Supported {
		return result
	}
	b.receiveOverflowMu.Lock()
	if b.receiveOverflowCarrier != carrier {
		b.receiveOverflowCarrier = carrier
		b.receiveOverflowBase = b.receiveOverflowTotal
		b.receiveOverflowRawLast = 0
	} else if observation.Packets < b.receiveOverflowRawLast {
		// The quic-go adapter extends the 32-bit kernel counter, but treat an
		// unexpected adapter reset as a new counter epoch instead of moving the
		// public cumulative value backwards.
		b.receiveOverflowBase = b.receiveOverflowTotal
	}
	before := b.receiveOverflowTotal
	b.receiveOverflowRawLast = observation.Packets
	b.receiveOverflowTotal = b.receiveOverflowBase + observation.Packets
	result.Packets = b.receiveOverflowTotal
	changed := b.receiveOverflowTotal > before
	b.receiveOverflowMu.Unlock()
	if changed {
		b.recordSessionEventAt(
			0, 0, telemetry.SessionEventReceiveOverflow, observation.Source, time.Now(),
			&telemetry.SessionEventMetrics{ReceiveQueueOverflow: before},
			&telemetry.SessionEventMetrics{ReceiveQueueOverflow: result.Packets},
		)
	}
	return result
}

// SessionTelemetry returns independent observations for the currently active
// QUIC sessions. Counters are scoped to a session and therefore reset when a
// configured endpoint reconnects with a new session generation.
func (b *Bind) SessionTelemetry() ([]telemetry.SessionObservation, uint64) {
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	if state == nil {
		return nil, 0
	}
	state.mu.Lock()
	sessions := make([]*session, 0, len(state.sessions))
	for _, sess := range state.sessions {
		sessions = append(sessions, sess)
	}
	state.mu.Unlock()
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].role != sessions[j].role {
			return sessions[i].role == "outbound"
		}
		return sessions[i].id < sessions[j].id
	})
	omitted := uint64(0)
	if len(sessions) > maxSessionTelemetry {
		omitted = uint64(len(sessions) - maxSessionTelemetry)
		sessions = sessions[:maxSessionTelemetry]
	}
	sampledAt := time.Now()
	result := make([]telemetry.SessionObservation, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, sess.telemetry(sampledAt))
	}
	return result, omitted
}

// RecentSessionTelemetry returns immutable final observations retained after
// sessions leave the active set. The list is ordered by FinalSequence. Entries
// are evicted when either the fixed capacity or TTL is exceeded.
func (b *Bind) RecentSessionTelemetry() ([]telemetry.ClosedSessionObservation, uint64) {
	b.telemetryMu.Lock()
	b.pruneRecentSessionsLocked(time.Now())
	result := append([]telemetry.ClosedSessionObservation(nil), b.recentSessions...)
	evicted := b.recentEvicted
	b.telemetryMu.Unlock()
	return result, evicted
}

func (b *Bind) pruneRecentSessionsLocked(now time.Time) {
	first := 0
	for first < len(b.recentSessions) &&
		now.Sub(b.recentSessions[first].ClosedAt) >= recentSessionTelemetryTTL {
		first++
	}
	if first == 0 {
		return
	}
	b.recentEvicted += uint64(first)
	copy(b.recentSessions, b.recentSessions[first:])
	b.recentSessions = b.recentSessions[:len(b.recentSessions)-first]
}

func (b *Bind) retainClosedSession(observation telemetry.ClosedSessionObservation) {
	b.telemetryMu.Lock()
	b.pruneRecentSessionsLocked(observation.ClosedAt)
	b.recentSequence++
	observation.FinalSequence = b.recentSequence
	if replacement := b.replacements[observation.SessionID]; replacement != 0 {
		observation.ReplacedBySessionID = replacement
		delete(b.replacements, observation.SessionID)
	}
	b.recentSessions = append(b.recentSessions, observation)
	if excess := len(b.recentSessions) - maxRecentSessionTelemetry; excess > 0 {
		b.recentEvicted += uint64(excess)
		copy(b.recentSessions, b.recentSessions[excess:])
		b.recentSessions = b.recentSessions[:len(b.recentSessions)-excess]
	}
	b.telemetryMu.Unlock()
}

// The caller holds state.mu. A missing closed record needs a pending link only
// while the old session can still publish its final observation; an evicted
// record will never be finalized again.
func (b *Bind) recordSessionReplacement(oldSessionID, newSessionID uint64, oldStillActive bool) {
	if oldSessionID == 0 || newSessionID == 0 {
		return
	}
	b.telemetryMu.Lock()
	for index := range b.recentSessions {
		if b.recentSessions[index].SessionID == oldSessionID {
			b.recentSessions[index].ReplacedBySessionID = newSessionID
			b.telemetryMu.Unlock()
			return
		}
	}
	if oldStillActive {
		b.replacements[oldSessionID] = newSessionID
	}
	b.telemetryMu.Unlock()
}

func sessionEventMetricsFromStats(
	stats telemetry.SessionStats,
	fecPolicy, endpoint string,
) *telemetry.SessionEventMetrics {
	return &telemetry.SessionEventMetrics{
		CongestionWindowBytes: stats.QUICCongestionWindowBytes,
		BytesInFlight:         stats.QUICBytesInFlight,
		BandwidthEstimateBps:  stats.QUICBandwidthEstimateBps,
		PacingRateBps:         stats.QUICPacingRateBps,
		SmoothedRTTUs:         stats.QUICSmoothedRTTUs,
		PathRTTUs:             stats.QUICPathRTTUs,
		QueueDelayUs:          stats.QUICQueueDelayUs,
		CongestionModelState:  stats.QUICCongestionModelState,
		PTOCount:              stats.QUICPTOCount,
		PacketsLost:           stats.QUICPacketsLost,
		SpuriousLossPackets:   stats.QUICSpuriousLossPackets,
		QueueDrops:            stats.QueueDrops,
		FECPolicy:             fecPolicy, Endpoint: endpoint,
	}
}

func transportEventMetrics(
	metrics *quiccarrier.ConnectionEventMetrics,
) *telemetry.SessionEventMetrics {
	if metrics == nil {
		return nil
	}
	return &telemetry.SessionEventMetrics{
		CongestionWindowBytes: metrics.CongestionWindowBytes,
		BytesInFlight:         metrics.BytesInFlight,
		BandwidthEstimateBps:  metrics.BandwidthEstimateBps,
		PacingRateBps:         metrics.PacingRateBps,
		SmoothedRTTUs:         metrics.SmoothedRTTUs,
		PathRTTUs:             metrics.PathRTTUs,
		QueueDelayUs:          metrics.QueueDelayUs,
		CongestionModelState:  metrics.CongestionModelState,
		PTOCount:              metrics.PTOCount,
		PacketsLost:           metrics.PacketsLost,
		SpuriousLossPackets:   metrics.SpuriousLossPackets,
	}
}

func (b *Bind) addQUICStats(stats *telemetry.Stats) {
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	if state == nil {
		return
	}
	state.mu.Lock()
	sessions := make([]*session, 0, len(state.sessions))
	for _, sess := range state.sessions {
		sessions = append(sessions, sess)
	}
	state.mu.Unlock()
	for _, sess := range sessions {
		stats.SendQueueDepth += uint64(len(sess.send))
		stats.SendQueueBytes += uint64(max(0, sess.sendBytes.Load()))
		stats.SendQueueBudgetBytes += uint64(sess.sendBudgetBytes.Load())
		stats.SendQueueDelayMaxUs = max(stats.SendQueueDelayMaxUs, sess.sendDelayMaxUs.Load())
		stats.PriorityQueueDepth += uint64(len(sess.priority))
		stats.ControlQueueDepth += uint64(len(sess.control))
		if sess.fecEncoder != nil {
			parity, lossEstimatePPM := sess.fecEncoder.Stats()
			stats.FECCurrentParityShards = max(stats.FECCurrentParityShards, uint64(parity))
			stats.FECLossEstimatePPM = max(stats.FECLossEstimatePPM, lossEstimatePPM)
		}
		sess.mu.Lock()
		conn := sess.conn
		sess.mu.Unlock()
		if conn == nil {
			continue
		}
		current := conn.Stats()
		stats.QUICBytesAcked += current.BytesAcked
		stats.QUICPacketsAcked += current.PacketsAcked
		stats.QUICBytesLost += current.BytesLost
		stats.QUICPacketsLost += current.PacketsLost
		stats.QUICSpuriousLossPackets += current.SpuriousLossPackets
		stats.QUICPTOCount += current.PTOCount
		stats.QUICCongestionWindowBytes += current.CongestionWindow
		stats.QUICBytesInFlight += current.BytesInFlight
		stats.QUICBandwidthEstimateBps += current.BandwidthEstimate
		stats.QUICPacingRateBps += current.PacingRate
		stats.QUICPathRTTUs = max(
			stats.QUICPathRTTUs,
			uint64(current.PropagationRTT/time.Microsecond),
		)
		stats.QUICQueueDelayUs = max(
			stats.QUICQueueDelayUs,
			uint64(current.QueueDelay/time.Microsecond),
		)
		stats.QUICFECRecoverableLossPPM = max(
			stats.QUICFECRecoverableLossPPM,
			current.FECRecoverableLossPPM,
		)
		stats.QUICFECResidualLossPPM = max(
			stats.QUICFECResidualLossPPM,
			current.FECResidualLossPPM,
		)
		stats.QUICCongestionModelState = max(
			stats.QUICCongestionModelState,
			current.CongestionModelState,
		)
		stats.QUICDatagramSendQueueLen += current.DatagramSendQueueLen
		stats.QUICDatagramSendQueueBytes += current.DatagramSendQueueBytes
		stats.QUICDatagramSendQueueBudget += current.DatagramSendQueueBudget
		stats.QUICDatagramSendQueueAgeUs = max(stats.QUICDatagramSendQueueAgeUs, uint64(current.DatagramSendQueueAge/time.Microsecond))
		stats.QUICDatagramRcvQueueLen += current.DatagramRcvQueueLen
		stats.QUICDatagramRcvQueueDrops += current.DatagramRcvQueueDrops
		stats.QUICDatagramRcvQueueHighWater = max(
			stats.QUICDatagramRcvQueueHighWater,
			current.DatagramRcvQueueHighWater,
		)
		minRTTUs := uint64(current.MinRTT / time.Microsecond)
		if minRTTUs != 0 && (stats.QUICMinRTTUs == 0 || minRTTUs < stats.QUICMinRTTUs) {
			stats.QUICMinRTTUs = minRTTUs
		}
		stats.QUICSmoothedRTTUs = max(
			stats.QUICSmoothedRTTUs,
			uint64(current.SmoothedRTT/time.Microsecond),
		)
		stats.QUICLatestRTTUs = max(
			stats.QUICLatestRTTUs,
			uint64(current.LatestRTT/time.Microsecond),
		)
		stats.QUICRTTVarUs = max(
			stats.QUICRTTVarUs,
			uint64(current.MeanDeviation/time.Microsecond),
		)
	}
}

// claimQueueDropEvent reports whether this caller should build the coalesced
// queue-drop telemetry snapshot and session event. Overload must not allocate
// per rejected packet, so only the first drop inside each interval claims the
// event; the queueDrops counters remain the per-packet signal.
func (s *session) claimQueueDropEvent(now time.Time) bool {
	if s.queueDropEventInterval <= 0 {
		return false
	}
	next := now.UnixNano()
	for {
		last := s.lastQueueDropEventNS.Load()
		if last != 0 && next-last < int64(s.queueDropEventInterval) {
			return false
		}
		if s.lastQueueDropEventNS.CompareAndSwap(last, next) {
			return true
		}
	}
}

// currentRemoteAddr reports the latest authenticated remote without taking
// the session mutex; the receive path calls this per datagram. A nil pointer
// (session constructed outside newSession) reads as the zero address.
func (s *session) currentRemoteAddr() netip.AddrPort {
	if p := s.remoteAddr.Load(); p != nil {
		return *p
	}
	return netip.AddrPort{}
}

func (s *session) telemetry(sampledAt time.Time) telemetry.SessionObservation {
	s.mu.Lock()
	conn := s.conn
	remoteAddr := s.currentRemoteAddr()
	establishedAt := s.establishedAt
	peers := make([]telemetry.SessionPeerObservation, 0, len(s.authenticatedPeers))
	for publicKey, generation := range s.authenticatedPeers {
		peers = append(peers, telemetry.SessionPeerObservation{
			PublicKey: publicKey, EndpointGeneration: generation, Authenticated: true,
		})
	}
	s.mu.Unlock()
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })

	state := "connecting"
	var establishedAtValue *time.Time
	if conn != nil {
		state = "established"
		copy := establishedAt
		establishedAtValue = &copy
	}
	currentEndpoint := ""
	if remoteAddr.IsValid() {
		currentEndpoint = remoteAddr.String()
	}
	stats := telemetry.SessionStats{
		WGTxPackets: s.stats.wgTxPackets.Load(), WGTxBytes: s.stats.wgTxBytes.Load(),
		WGRxPackets: s.stats.wgRxPackets.Load(), WGRxBytes: s.stats.wgRxBytes.Load(),
		WireTxPackets: s.stats.wireTxPackets.Load(), WireTxBytes: s.stats.wireTxBytes.Load(),
		WireRxPackets: s.stats.wireRxPackets.Load(), WireRxBytes: s.stats.wireRxBytes.Load(),
		SendQueueBytes:       uint64(max(0, s.sendBytes.Load())),
		SendQueueBudgetBytes: uint64(s.sendBudgetBytes.Load()),
		SendQueueDelayMaxUs:  s.sendDelayMaxUs.Load(),
		SendQueueExpired:     s.stats.sendQueueExpired.Load(),
		QueueDrops:           s.stats.queueDrops.Load(), FECDataTx: s.stats.fecDataTx.Load(),
		FECParityTx: s.stats.fecParityTx.Load(), FECRawLost: s.stats.fecRawLost.Load(),
		FECRecovered: s.stats.fecRecovered.Load(), FECUnrecovered: s.stats.fecUnrecovered.Load(),
		SendQueueDepth: uint64(len(s.send)), PriorityQueueDepth: uint64(len(s.priority)),
		ControlQueueDepth: uint64(len(s.control)),
	}
	if s.fecEncoder != nil {
		parity, lossEstimatePPM := s.fecEncoder.Stats()
		stats.FECCurrentParityShards = uint64(parity)
		stats.FECLossEstimatePPM = lossEstimatePPM
	}
	if conn != nil {
		current := conn.Stats()
		stats.QUICBytesSent = current.BytesSent
		stats.QUICPacketsSent = current.PacketsSent
		stats.QUICBytesReceived = current.BytesReceived
		stats.QUICPacketsReceived = current.PacketsReceived
		stats.QUICBytesAcked = current.BytesAcked
		stats.QUICPacketsAcked = current.PacketsAcked
		stats.QUICBytesLost = current.BytesLost
		stats.QUICPacketsLost = current.PacketsLost
		stats.QUICSpuriousLossPackets = current.SpuriousLossPackets
		stats.QUICPTOCount = current.PTOCount
		stats.QUICMinRTTUs = uint64(current.MinRTT / time.Microsecond)
		stats.QUICLatestRTTUs = uint64(current.LatestRTT / time.Microsecond)
		stats.QUICSmoothedRTTUs = uint64(current.SmoothedRTT / time.Microsecond)
		stats.QUICRTTVarUs = uint64(current.MeanDeviation / time.Microsecond)
		stats.QUICCongestionWindowBytes = current.CongestionWindow
		stats.QUICBytesInFlight = current.BytesInFlight
		stats.QUICBandwidthEstimateBps = current.BandwidthEstimate
		stats.QUICPacingRateBps = current.PacingRate
		stats.QUICPathRTTUs = uint64(current.PropagationRTT / time.Microsecond)
		stats.QUICQueueDelayUs = uint64(current.QueueDelay / time.Microsecond)
		stats.QUICFECRecoverableLossPPM = current.FECRecoverableLossPPM
		stats.QUICFECResidualLossPPM = current.FECResidualLossPPM
		stats.QUICCongestionModelState = current.CongestionModelState
		stats.QUICDatagramSendQueueLen = current.DatagramSendQueueLen
		stats.QUICDatagramSendQueueBytes = current.DatagramSendQueueBytes
		stats.QUICDatagramSendQueueBudget = current.DatagramSendQueueBudget
		stats.QUICDatagramSendQueueAgeUs = uint64(current.DatagramSendQueueAge / time.Microsecond)
		stats.QUICDatagramRcvQueueLen = current.DatagramRcvQueueLen
		stats.QUICDatagramRcvQueueDrops = current.DatagramRcvQueueDrops
		stats.QUICDatagramRcvQueueHighWater = current.DatagramRcvQueueHighWater
	}
	return telemetry.SessionObservation{
		TelemetryVersion: telemetry.SessionTelemetryVersion,
		SessionID:        s.id, SessionGeneration: s.generation,
		Role: s.role, State: state, ConfiguredEndpoint: s.configuredEndpoint,
		CurrentEndpoint: currentEndpoint, EstablishedAt: establishedAtValue,
		SampledAt: sampledAt, Peers: peers, ReplacesSessionID: s.replacesSessionID,
		Stats: stats,
	}
}

func (s *session) setCloseCause(reason, class string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeReason != "" && s.closeReason != telemetry.SessionCloseUnknown {
		return
	}
	if reason == "" {
		reason = telemetry.SessionCloseUnknown
	}
	s.closeReason = reason
	s.closeErrorClass = class
	if err == nil {
		return
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	if len(message) > 512 {
		message = message[:512]
	}
	s.closeError = message
}

func (s *session) finalTelemetry(closedAt time.Time) telemetry.ClosedSessionObservation {
	active := s.telemetry(closedAt)
	s.mu.Lock()
	reason, class, lastError := s.closeReason, s.closeErrorClass, s.closeError
	s.mu.Unlock()
	if reason == "" {
		reason = telemetry.SessionCloseUnknown
	}
	return telemetry.ClosedSessionObservation{
		TelemetryVersion: telemetry.RecentSessionTelemetryVersion,
		SessionID:        active.SessionID, SessionGeneration: active.SessionGeneration,
		Role: active.Role, State: "closed",
		ConfiguredEndpoint: active.ConfiguredEndpoint,
		CurrentEndpoint:    active.CurrentEndpoint,
		EstablishedAt:      active.EstablishedAt, ClosedAt: closedAt, SampledAt: closedAt,
		Peers: active.Peers, CloseReason: reason, ErrorClass: class,
		LastError: lastError, ReplacesSessionID: active.ReplacesSessionID,
		Final: true, FinalStats: active.Stats,
	}
}

func (s *session) recordTransportEvent(event quiccarrier.ConnectionEvent) {
	eventType := event.Type
	switch event.Type {
	case "controller_state":
		eventType = telemetry.SessionEventControllerState
	case "cwnd_reduction":
		eventType = telemetry.SessionEventCwndReduction
	case "pto":
		eventType = telemetry.SessionEventPTO
	case "loss":
		eventType = telemetry.SessionEventLoss
	case "spurious_loss":
		eventType = telemetry.SessionEventSpuriousLoss
	case "path_rtt":
		eventType = telemetry.SessionEventPathRTT
	}
	s.endpoint.owner.recordSessionEventAt(
		s.id, s.generation, eventType, event.Reason, event.WallTime,
		transportEventMetrics(event.Before), transportEventMetrics(event.After),
	)
}
