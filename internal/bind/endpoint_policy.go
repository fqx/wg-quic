package armorbind

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/RC-CHN/wg-quic/internal/peerendpoint"
	"github.com/RC-CHN/wg-quic/internal/transport/obfs"
)

// AcquireEndpointKey associates a runtime-selected numeric endpoint with its
// peer's Salamander key. The returned release is reference-counted.
func (b *Bind) AcquireEndpointKey(endpoint netip.AddrPort, key obfs.Key) (func(), error) {
	endpoint, err := peerendpoint.Canonical(endpoint)
	if err != nil {
		return nil, fmt.Errorf("valid numeric endpoint is required: %w", err)
	}
	b.mu.Lock()
	lease, ok := b.obfsDynamic[endpoint]
	if ok && lease.key != key {
		b.mu.Unlock()
		return nil, fmt.Errorf("endpoint %s is already associated with a different obfuscation key", endpoint)
	}
	lease.key = key
	lease.refs++
	b.obfsDynamic[endpoint] = lease
	b.obfsResolved[endpoint] = key
	state := b.state
	if state != nil {
		state.carrier.AssociateEndpoint(endpoint, key)
	}
	b.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() { b.releaseEndpointKey(endpoint, key) })
	}, nil
}

func (b *Bind) releaseEndpointKey(endpoint netip.AddrPort, key obfs.Key) {
	b.mu.Lock()
	lease, ok := b.obfsDynamic[endpoint]
	if !ok || lease.key != key {
		b.mu.Unlock()
		return
	}
	lease.refs--
	if lease.refs > 0 {
		b.obfsDynamic[endpoint] = lease
		b.mu.Unlock()
		return
	}
	delete(b.obfsDynamic, endpoint)
	delete(b.obfsResolved, endpoint)
	state := b.state
	if state != nil {
		state.carrier.DisassociateEndpoint(endpoint, key)
	}
	b.mu.Unlock()
}

func normalizeFECPolicy(policy string) (string, error) {
	if policy == "" {
		policy = "balanced"
	}
	switch policy {
	case "latency", "balanced", "throughput":
		return policy, nil
	default:
		return "", fmt.Errorf("unsupported peer FEC policy %q", policy)
	}
}

// AcquireEndpointFECPolicy associates an outbound endpoint with one peer FEC
// encoder policy. Different policies cannot share one configured endpoint,
// because WireGuard's outbound endpoint does not carry peer identity into the
// bind interface.
func (b *Bind) AcquireEndpointFECPolicy(
	endpoint netip.AddrPort,
	policy string,
) (func(), error) {
	endpoint, err := peerendpoint.Canonical(endpoint)
	if err != nil {
		return nil, fmt.Errorf("valid numeric endpoint is required: %w", err)
	}
	policy, err = normalizeFECPolicy(policy)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	lease := b.fecPolicies[endpoint]
	if lease.refs != 0 && lease.policy != policy {
		b.mu.Unlock()
		return nil, fmt.Errorf("endpoint %s is already associated with FEC policy %q", endpoint, lease.policy)
	}
	lease.policy = policy
	lease.refs++
	b.fecPolicies[endpoint] = lease
	state := b.state
	b.mu.Unlock()
	b.applyEndpointFECPolicy(state, endpoint, policy)
	return b.endpointFECPolicyRelease(endpoint, policy), nil
}

// ReplaceEndpointFECPolicy atomically changes the sole policy lease for an
// endpoint. The send worker flushes the old group before applying it.
func (b *Bind) ReplaceEndpointFECPolicy(
	endpoint netip.AddrPort,
	oldPolicy string,
	newPolicy string,
) (func(), error) {
	endpoint, err := peerendpoint.Canonical(endpoint)
	if err != nil {
		return nil, err
	}
	oldPolicy, err = normalizeFECPolicy(oldPolicy)
	if err != nil {
		return nil, err
	}
	newPolicy, err = normalizeFECPolicy(newPolicy)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	lease := b.fecPolicies[endpoint]
	if lease.refs != 1 || lease.policy != oldPolicy {
		b.mu.Unlock()
		return nil, fmt.Errorf("endpoint %s FEC policy lease changed concurrently", endpoint)
	}
	lease.policy = newPolicy
	b.fecPolicies[endpoint] = lease
	state := b.state
	b.mu.Unlock()
	b.applyEndpointFECPolicy(state, endpoint, newPolicy)
	return b.endpointFECPolicyRelease(endpoint, newPolicy), nil
}

func (b *Bind) endpointFECPolicyRelease(endpoint netip.AddrPort, policy string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			lease := b.fecPolicies[endpoint]
			if lease.refs == 0 || lease.policy != policy {
				b.mu.Unlock()
				return
			}
			lease.refs--
			if lease.refs == 0 {
				delete(b.fecPolicies, endpoint)
			} else {
				b.fecPolicies[endpoint] = lease
			}
			b.mu.Unlock()
		})
	}
}

func (b *Bind) applyEndpointFECPolicy(
	state *runState,
	endpoint netip.AddrPort,
	policy string,
) {
	if state == nil {
		return
	}
	state.mu.Lock()
	ep := state.endpoints[endpoint]
	if ep == nil {
		state.mu.Unlock()
		return
	}
	ep.mu.Lock()
	ep.fecPolicy = policy
	sess := ep.session
	ep.mu.Unlock()
	state.mu.Unlock()
	if sess != nil {
		sess.setFECPolicy(policy)
	}
}

// SetAuthenticatedSessionFECPolicy binds an accepted/roamed connection only
// after WireGuard identifies the peer that authenticated on that path.
func (b *Bind) SetAuthenticatedSessionFECPolicy(sessionID uint64, policy string) error {
	if sessionID == 0 {
		return nil
	}
	policy, err := normalizeFECPolicy(policy)
	if err != nil {
		return err
	}
	b.mu.Lock()
	state := b.state
	b.mu.Unlock()
	if state == nil {
		return nil
	}
	state.mu.Lock()
	sess := state.sessions[sessionID]
	state.mu.Unlock()
	if sess != nil {
		sess.setFECPolicy(policy)
	}
	return nil
}

type fecPolicyProfile struct {
	name          string
	dataShards    int
	interleave    int
	flushDeadline time.Duration
}

func fecPolicyProfileFor(cfg Config, policy string) fecPolicyProfile {
	policy, err := normalizeFECPolicy(policy)
	if err != nil {
		policy = "balanced"
	}
	profile := fecPolicyProfile{
		name: policy, dataShards: cfg.FECDataShards,
		interleave: cfg.FECInterleave, flushDeadline: cfg.FECFlushDeadline,
	}
	switch policy {
	case "latency":
		profile.dataShards = min(profile.dataShards, 4)
		profile.interleave = 1
		profile.flushDeadline = min(profile.flushDeadline, time.Millisecond)
	case "throughput":
		profile.interleave = max(profile.interleave, 2)
		profile.flushDeadline = max(profile.flushDeadline, 4*time.Millisecond)
	}
	if profile.flushDeadline <= 0 {
		profile.flushDeadline = time.Millisecond
	}
	return profile
}

func (s *session) setFECPolicy(policy string) {
	if s.fecPolicyUpdates == nil || s.closed.Load() {
		return
	}
	select {
	case s.fecPolicyUpdates <- policy:
		return
	default:
	}
	// Only the newest requested profile matters. The send worker is the sole
	// encoder owner and will still flush whichever profile is active there.
	select {
	case <-s.fecPolicyUpdates:
	default:
	}
	select {
	case s.fecPolicyUpdates <- policy:
	default:
	}
}

func (s *session) currentFECPolicy() string {
	s.mu.Lock()
	policy := s.fecPolicy
	s.mu.Unlock()
	return policy
}
