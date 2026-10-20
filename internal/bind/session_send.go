package armorbind

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/RC-CHN/wg-quic/internal/telemetry"
	"github.com/RC-CHN/wg-quic/internal/transport/fec"
	quiccarrier "github.com/RC-CHN/wg-quic/internal/transport/quic"
)

func (s *session) sendLoop() {
	select {
	case <-s.ready:
	case <-s.ctx.Done():
		return
	}
	s.mu.Lock()
	qconn := s.conn
	s.mu.Unlock()
	if s.fecEncoder != nil {
		// Start with ordinary writes while the FEC controller assesses the
		// path. Grouped data shards can otherwise be lost together by a queue
		// or shaper operating before segmentation, defeating their parity.
		qconn.SetGSOBatchingEnabled(false)
	}
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	timerActive := false
	defer timer.Stop()
	var budgetUpdated time.Time

	sendPacket := func(packet []byte) bool {
		packetBytes := len(packet)
		kind, fecPacket := fec.PacketKind(packet)
		if err := qconn.SendDatagramOwnedContext(s.ctx, packet); err != nil {
			quiccarrier.ReleaseDatagramSendBuffer(packet)
			if s.ctx.Err() == nil {
				reason, class, message := quiccarrier.ClassifyConnectionError(err)
				s.setCloseCause(reason, class, errors.New(message))
				s.endpoint.owner.debugf("QUIC send stopped: session=%d remote=%s error=%v", s.id, s.endpoint.addr, err)
			}
			return false
		}
		s.endpoint.owner.stats.wireTxPackets.Add(1)
		s.endpoint.owner.stats.wireTxBytes.Add(uint64(packetBytes))
		s.stats.wireTxPackets.Add(1)
		s.stats.wireTxBytes.Add(uint64(packetBytes))
		if fecPacket {
			switch kind {
			case fec.KindData:
				s.endpoint.owner.stats.fecDataTx.Add(1)
				s.stats.fecDataTx.Add(1)
			case fec.KindParity:
				s.endpoint.owner.stats.fecParityTx.Add(1)
				s.stats.fecParityTx.Add(1)
			}
		}
		return true
	}
	sendPackets := func(packets [][]byte) bool {
		for _, packet := range packets {
			if !sendPacket(packet) {
				return false
			}
		}
		return true
	}
	stopTimer := func() {
		if timerActive && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerActive = false
	}
	resetTimer := func() {
		stopTimer()
		timer.Reset(s.fecEncoder.FlushDelay(s.fecFlushDeadline))
		timerActive = true
	}
	applyFECPolicy := func(policy string) bool {
		if s.fecEncoder == nil {
			return true
		}
		profile := fecPolicyProfileFor(s.state.cfg, policy)
		previousPolicy := s.currentFECPolicy()
		if profile.name == previousPolicy {
			return true
		}
		stopTimer()
		packets, err := s.fecEncoder.Reconfigure(profile.dataShards, profile.interleave)
		if err != nil || !sendPackets(packets) {
			return false
		}
		s.mu.Lock()
		s.fecPolicy = profile.name
		s.fecFlushDeadline = profile.flushDeadline
		s.mu.Unlock()
		s.endpoint.owner.recordSessionEventAt(
			s.id, s.generation, telemetry.SessionEventFECPolicy, "runtime_update",
			time.Now(),
			&telemetry.SessionEventMetrics{FECPolicy: previousPolicy},
			&telemetry.SessionEventMetrics{FECPolicy: profile.name},
		)
		return true
	}
	sendFrame := func(frame []byte) bool {
		if s.fecEncoder == nil {
			return sendPacket(frame)
		}
		s.fecPathSampleFrames++
		if s.fecPathSampleFrames%32 == 0 {
			stats := qconn.Stats()
			s.fecEncoder.ObservePathRTT(stats.PropagationRTT)
			s.fecEncoder.ObserveTransport(stats.PacketsSent, stats.PacketsLost)
			parity, lossPPM := s.fecEncoder.Stats()
			// Keep the initial delivery samples on ordinary writes. Enabling
			// batches during model startup can slow the bandwidth ramp even
			// on a clean path. Residual loss also keeps batching suppressed.
			pastStartup := s.state.cfg.CongestionMode != "model" || stats.CongestionModelState != 0
			qconn.SetGSOBatchingEnabled(parity == 0 && lossPPM == 0 && pastStartup)
		}
		previousFlushDelay := s.fecEncoder.FlushDelay(s.fecFlushDeadline)
		packets, err := s.fecEncoder.Add(frame)
		if err != nil || !sendPackets(packets) {
			return false
		}
		if s.fecEncoder.Pending() {
			if !timerActive || s.fecEncoder.FlushDelay(s.fecFlushDeadline) != previousFlushDelay {
				// Reconfiguring interleave closes every old group. Start the
				// new lane window from its first source, not the old deadline.
				resetTimer()
			}
		} else {
			stopTimer()
		}
		return true
	}
	sendWGPacket := func(packet outboundPacket) bool {
		now := time.Now()
		if now.Sub(budgetUpdated) >= 10*time.Millisecond {
			stats := qconn.Stats()
			s.updateSendBudget(stats.BandwidthEstimate, stats.PacingRate, s.state.cfg.CongestionMode == "model" && stats.CongestionModelState == 0)
			budgetUpdated = now
		}
		s.releaseSendBytes(packet)
		if !packet.queuedAt.IsZero() {
			delay := uint64(max(0, now.Sub(packet.queuedAt).Microseconds()))
			for _, counter := range []*atomic.Uint64{&s.sendDelayMaxUs, &s.endpoint.owner.stats.sendDelayMaxUs} {
				for old := counter.Load(); delay > old; old = counter.Load() {
					if counter.CompareAndSwap(old, delay) {
						break
					}
				}
			}
		}
		if !packet.queuedAt.IsZero() && now.Sub(packet.queuedAt) > s.sendMaxAge() {
			quiccarrier.ReleaseDatagramSendBuffer(packet.preparedFrame)
			s.recordSendDrop("send_queue_expired")
			return true
		}
		fragmentData := qconn.MaxDatagramPayloadSize() - frameHeaderSize
		if s.fecEncoder != nil {
			fragmentData -= fec.DataPacketOverhead
		}
		fragmentData = min(fragmentData, maxFragmentData)
		payload := packet.preparedFrame[frameHeaderSize:]
		if len(payload) <= fragmentData {
			frame, err := framePreparedPacket(packet.preparedFrame, packet.id)
			return err == nil && sendFrame(frame)
		}
		frames, err := fragmentPacketSized(payload, packet.id, fragmentData)
		if err != nil {
			return false
		}
		for _, frame := range frames {
			if !sendFrame(frame) {
				return false
			}
		}
		return true
	}

	for {
		select {
		case policy := <-s.fecPolicyUpdates:
			if !applyFECPolicy(policy) {
				return
			}
			continue
		default:
		}
		select {
		case policy := <-s.fecPolicyUpdates:
			if !applyFECPolicy(policy) {
				return
			}
		case packet := <-s.send:
			if !sendWGPacket(packet) {
				return
			}
		case <-timer.C:
			timerActive = false
			if s.fecEncoder != nil {
				packets, err := s.fecEncoder.Flush()
				if err != nil || !sendPackets(packets) {
					return
				}
			}
		case <-s.ctx.Done():
			return
		}
	}
}
