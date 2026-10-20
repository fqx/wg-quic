package armorbind

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/RC-CHN/wg-quic/internal/telemetry"
)

// sessionEventLog owns event retention and cursor semantics independently of
// connection management. Once full, append overwrites one ring slot in O(1).
// Only readers allocate a chronological snapshot, bounded by the page limit.
type sessionEventLog struct {
	mu       sync.Mutex
	origin   time.Time
	streamID string
	sequence uint64
	dropped  uint64
	entries  []telemetry.SessionEvent
	first    int
}

func newSessionEventLog() sessionEventLog {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return sessionEventLog{origin: time.Now(), streamID: hex.EncodeToString(id[:])}
}

// SessionEvents returns a bounded cursor page. A stream mismatch is an epoch
// boundary, never an empty event range.
func (b *Bind) SessionEvents(streamID string, after uint64, limit int) (telemetry.SessionEventBatch, error) {
	return b.events.page(streamID, after, limit)
}

func (h *sessionEventLog) page(streamID string, after uint64, limit int) (telemetry.SessionEventBatch, error) {
	if limit <= 0 {
		limit = 256
	}
	limit = min(limit, maxSessionEventQuery)
	h.mu.Lock()
	defer h.mu.Unlock()
	if streamID != "" && streamID != h.streamID {
		return telemetry.SessionEventBatch{}, fmt.Errorf("event stream changed from %s to %s", streamID, h.streamID)
	}
	now := time.Now()
	batch := telemetry.SessionEventBatch{
		TelemetryVersion: telemetry.SessionEventTelemetryVersion,
		EventStreamID:    h.streamID, EventsDroppedTotal: h.dropped,
		LastSequence: min(after, h.sequence), SampledAt: now,
		MonotonicElapsedNS: max(0, now.Sub(h.origin).Nanoseconds()),
	}
	if len(h.entries) == 0 {
		return batch, nil
	}
	at := func(i int) telemetry.SessionEvent { return h.entries[(h.first+i)%len(h.entries)] }
	batch.FirstAvailableSequence = at(0).EventSequence
	first := sort.Search(len(h.entries), func(i int) bool { return at(i).EventSequence > after })
	last := min(len(h.entries), first+limit)
	if last > first {
		batch.Events = make([]telemetry.SessionEvent, last-first)
		for i := range batch.Events {
			batch.Events[i] = at(first + i)
		}
		batch.LastSequence = batch.Events[len(batch.Events)-1].EventSequence
	}
	return batch, nil
}

func (b *Bind) recordSessionEventAt(
	id, generation uint64, kind, reason string, wall time.Time,
	before, after *telemetry.SessionEventMetrics,
) {
	b.events.append(telemetry.SessionEvent{
		SessionID: id, SessionGeneration: generation,
		EventType: kind, Reason: reason, WallTime: wall, Before: before, After: after,
	})
}

func (h *sessionEventLog) append(event telemetry.SessionEvent) {
	if event.WallTime.IsZero() {
		event.WallTime = time.Now()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sequence++
	event.TelemetryVersion = telemetry.SessionEventTelemetryVersion
	event.EventStreamID = h.streamID
	event.EventSequence = h.sequence
	event.MonotonicElapsedNS = max(0, event.WallTime.Sub(h.origin).Nanoseconds())
	if len(h.entries) < maxSessionEvents {
		h.entries = append(h.entries, event)
		return
	}
	h.entries[h.first] = event
	h.first = (h.first + 1) % len(h.entries)
	h.dropped++
}
