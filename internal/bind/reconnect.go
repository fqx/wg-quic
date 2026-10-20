package armorbind

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/RC-CHN/wg-quic/internal/telemetry"
)

// RetireEndpoint closes the configured outbound session for an old endpoint.
// It does not affect accepted connection-scoped endpoints used for roaming.
func (b *Bind) RetireEndpoint(endpoint netip.AddrPort) {
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	if state == nil {
		return
	}
	state.mu.Lock()
	ep := state.endpoints[endpoint]
	delete(state.endpoints, endpoint)
	state.mu.Unlock()
	if ep == nil {
		return
	}
	ep.mu.Lock()
	ep.retired = true
	ep.activated = false
	ep.cancelReconnectLocked()
	session := ep.session
	ep.session = nil
	ep.mu.Unlock()
	if session != nil {
		session.setCloseCause(
			telemetry.SessionCloseConfigurationRemoved,
			"configuration_removed",
			nil,
		)
		session.cancel()
	}
}

// RedialEndpoint closes the current configured session while retaining the
// endpoint object and immediately starts a fresh QUIC session.
func (b *Bind) RedialEndpoint(endpoint netip.AddrPort) {
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	if state == nil {
		return
	}
	state.mu.Lock()
	ep := state.endpoints[endpoint]
	state.mu.Unlock()
	if ep == nil {
		return
	}
	ep.mu.Lock()
	ep.cancelReconnectLocked()
	session := ep.session
	ep.session = nil
	ep.mu.Unlock()
	if session != nil {
		ep.mu.Lock()
		ep.pendingReplacement = session.id
		ep.mu.Unlock()
		session.setCloseCause(
			telemetry.SessionCloseEndpointReplaced,
			"endpoint_replaced",
			nil,
		)
		session.cancel()
	}
	b.scheduleEndpointReconnect(state, ep, true)
}

func (b *Bind) scheduleEndpointReconnect(
	state *runState,
	ep *Endpoint,
	immediate bool,
) {
	ep.mu.Lock()
	if !ep.isConfigured() || !ep.activated || ep.retired ||
		ep.session != nil || state.ctx.Err() != nil {
		ep.mu.Unlock()
		return
	}
	if ep.reconnectScheduled {
		if !immediate {
			ep.mu.Unlock()
			return
		}
		ep.cancelReconnectLocked()
	}
	delay := time.Duration(0)
	if !immediate && ep.consecutiveFailures > 0 {
		delay = reconnectBackoff(
			state.cfg.ReconnectMin,
			state.cfg.ReconnectMax,
			ep.consecutiveFailures-1,
		)
		delay = state.cfg.ReconnectJitter(delay)
		if delay < 0 {
			delay = 0
		}
	}
	ctx, cancel := context.WithCancel(state.ctx)
	ep.reconnectGeneration++
	generation := ep.reconnectGeneration
	ep.reconnectScheduled = true
	ep.reconnectCancel = cancel
	if delay > 0 {
		ep.nextReconnect = time.Now().Add(delay)
	} else {
		ep.nextReconnect = time.Time{}
	}
	remote := ep.addr
	ep.mu.Unlock()

	started := state.startWorker(func() {
		defer cancel()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		ep.mu.Lock()
		if ep.reconnectGeneration != generation || !ep.reconnectScheduled {
			ep.mu.Unlock()
			return
		}
		ep.reconnectScheduled = false
		ep.reconnectCancel = nil
		ep.nextReconnect = time.Time{}
		eligible := ep.isConfigured() && ep.activated && !ep.retired && ep.session == nil
		ep.mu.Unlock()
		if !eligible || state.ctx.Err() != nil {
			return
		}
		if b.hasEstablishedSession(state, remote) {
			return
		}
		if _, err := b.sessionForEndpoint(state, ep, true); err != nil && state.ctx.Err() == nil {
			b.debugf("start maintained QUIC session: remote=%s error=%v", remote, err)
			// Admission pressure is temporary. No session was created to
			// schedule another attempt on close, so retain maintenance here.
			// Back off just as for a failed dial; never spin at zero delay.
			if errors.Is(err, errSessionAdmissionLimit) {
				ep.mu.Lock()
				ep.consecutiveFailures++
				ep.mu.Unlock()
				b.scheduleEndpointReconnect(state, ep, false)
			}
		}
	})
	if started {
		b.debugf("scheduled QUIC reconnect: remote=%s delay=%s", remote, delay)
		return
	}
	ep.mu.Lock()
	if ep.reconnectGeneration == generation {
		ep.cancelReconnectLocked()
	}
	ep.mu.Unlock()
}

func reconnectBackoff(minimum, maximum time.Duration, exponent uint32) time.Duration {
	value := minimum
	for range exponent {
		if value >= maximum/2 {
			return maximum
		}
		value *= 2
	}
	return min(value, maximum)
}

func (b *Bind) hasEstablishedSession(state *runState, remote netip.AddrPort) bool {
	state.mu.Lock()
	sessions := make([]*session, 0, 1)
	for _, candidate := range state.sessions {
		if candidate.endpoint.addr == remote &&
			!candidate.closed.Load() && candidate.ctx.Err() == nil {
			sessions = append(sessions, candidate)
		}
	}
	state.mu.Unlock()
	for _, candidate := range sessions {
		candidate.mu.Lock()
		established := candidate.conn != nil
		candidate.mu.Unlock()
		if established {
			return true
		}
	}
	return false
}

func (b *Bind) suspendConfiguredReconnect(state *runState, remote netip.AddrPort) {
	state.mu.Lock()
	ep := state.endpoints[remote]
	state.mu.Unlock()
	if ep == nil {
		return
	}
	ep.mu.Lock()
	ep.consecutiveFailures = 0
	ep.cancelReconnectLocked()
	ep.mu.Unlock()
}

func (b *Bind) resumeConfiguredReconnect(state *runState, remote netip.AddrPort) {
	state.mu.Lock()
	ep := state.endpoints[remote]
	state.mu.Unlock()
	if ep != nil {
		b.scheduleEndpointReconnect(state, ep, true)
	}
}
