package armorbind

import (
	"errors"

	"github.com/RC-CHN/wg-quic/internal/telemetry"
)

var errSessionAdmissionLimit = errors.New("session admission limit")

// state.mu protects both admission and registration. Inbound caps leave room
// for configured outbound peers even when strangers fill the inbound budget.
func (s *runState) admitSessionLocked(inbound bool) bool {
	return len(s.sessions) < s.cfg.MaxSessions && (!inbound ||
		(s.inboundSessions < s.cfg.MaxInboundSessions && s.pendingInbound < s.cfg.MaxPendingInboundSessions))
}

func (s *session) expireAuthentication() {
	s.state.mu.Lock()
	expired := !s.closed.Load() && s.authentication.CompareAndSwap(0, 2)
	if expired {
		s.state.pendingInbound--
	}
	s.state.mu.Unlock()
	if !expired {
		return
	}
	s.endpoint.owner.stats.authenticationTimeouts.Add(1)
	s.setCloseCause(telemetry.SessionCloseAuthenticationTimeout, "authentication_timeout", errors.New("WireGuard authentication deadline exceeded"))
	s.close()
}

// Unauthenticated traffic cannot occupy the whole shared WireGuard queue.
// Authenticated traffic retains the existing allocation-free enqueue path.
func (s *session) reserveUnauthenticatedReceive() bool {
	limit := int32(min(32, max(1, s.state.cfg.QueueSize/4)))
	if s.pendingReceive.Add(1) <= limit {
		return true
	}
	s.pendingReceive.Add(-1)
	return false
}

func (p receivedPacket) dispose() {
	if p.reservation != nil {
		p.reservation.pendingReceive.Add(-1)
	}
	if p.release != nil {
		p.release(p.data)
	}
}

// AssociateSessionPeer records that WireGuard authenticated a packet from a
// peer on the named QUIC session. A session can carry more than one peer, so
// associations are accumulated rather than replaced.
func (b *Bind) AssociateSessionPeer(
	sessionID uint64,
	publicKey string,
	endpointGeneration uint64,
) bool {
	if sessionID == 0 || publicKey == "" {
		return false
	}
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	if state == nil {
		return false
	}
	state.mu.Lock()
	sess := state.sessions[sessionID]
	if sess != nil && !sess.closed.Load() {
		if sess.authentication.CompareAndSwap(0, 1) && sess.role == "inbound" {
			state.pendingInbound--
		}
		if sess.authentication.Load() == 2 {
			sess = nil
		}
	}
	state.mu.Unlock()
	if sess == nil || sess.closed.Load() {
		return false
	}
	sess.mu.Lock()
	if previous := sess.authenticatedPeers[publicKey]; endpointGeneration < previous {
		endpointGeneration = previous
	}
	sess.authenticatedPeers[publicKey] = endpointGeneration
	sess.mu.Unlock()
	return true
}
