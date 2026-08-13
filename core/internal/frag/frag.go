package frag

import (
	"time"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/protocol"
)

const (
	// defraggerTimeout is how long an incomplete fragment group is kept.
	// Fragments of one message are written back-to-back into the same QUIC
	// connection and are never retransmitted, so a fragment that hasn't shown
	// up by now is gone for good - the only reason to wait at all is
	// reordering on a high-latency path.
	defraggerTimeout = 10 * time.Second

	// defraggerMaxEntries caps the number of fragment groups being reassembled
	// at once. Applications rarely have more than a couple of oversized packets
	// in flight, so this mostly exists to bound what a peer that only ever
	// sends first fragments can pin down for the lifetime of a session.
	defraggerMaxEntries = 8

	// defraggerMaxMessageSize caps a reassembled message. No UDP payload can be
	// larger than this on any network, so a group claiming more is malformed no
	// matter how large a packet the two ends are willing to relay to each other.
	defraggerMaxMessageSize = 65535
)

func FragUDPMessage(m *protocol.UDPMessage, maxSize int) []protocol.UDPMessage {
	if m.Size() <= maxSize {
		return []protocol.UDPMessage{*m}
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	if maxPayloadSize <= 0 {
		return nil
	}
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize) // round up
	frags := make([]protocol.UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags
}

// defraggerEntry is the reassembly state of one fragment group.
type defraggerEntry struct {
	frags []*protocol.UDPMessage
	count uint8
	size  int       // data size
	last  time.Time // when the most recent fragment of this group arrived
}

// Defragger handles the defragmentation of UDP messages.
// Groups are keyed by PacketID - which identifies a fragment group, not a
// packet sequence - so several oversized packets can be reassembled at once
// even if their fragments arrive interleaved. A group that stops making
// progress is dropped after defraggerTimeout, and no more than
// defraggerMaxEntries groups are tracked at any time.
//
// Defragger is not safe for concurrent use: both the client and the server
// feed all of a session's messages from a single goroutine.
type Defragger struct {
	entries    map[uint16]*defraggerEntry
	timeout    time.Duration
	maxEntries int
	now        func() time.Time // replaced in tests
}

func NewDefragger() *Defragger {
	d := &Defragger{}
	d.init()
	return d
}

// init fills in whatever is still zero, so that a Defragger created as a bare
// struct literal behaves like one from NewDefragger.
func (d *Defragger) init() {
	if d.entries == nil {
		d.entries = make(map[uint16]*defraggerEntry)
	}
	if d.timeout <= 0 {
		d.timeout = defraggerTimeout
	}
	if d.maxEntries <= 0 {
		d.maxEntries = defraggerMaxEntries
	}
	if d.now == nil {
		d.now = time.Now
	}
}

func (d *Defragger) Feed(m *protocol.UDPMessage) *protocol.UDPMessage {
	if m.FragCount <= 1 {
		return m
	}
	if m.FragID >= m.FragCount {
		// wtf is this?
		return nil
	}
	d.init()
	now := d.now()
	d.sweep(now)

	e := d.entries[m.PacketID]
	if e == nil || len(e.frags) != int(m.FragCount) {
		// Either a group we haven't seen yet, or a PacketID reused with a
		// different fragment count - in both cases nothing that is already
		// stored under this ID can ever complete, so start over.
		if e == nil && len(d.entries) >= d.maxEntries {
			d.evictOldest()
		}
		e = &defraggerEntry{frags: make([]*protocol.UDPMessage, m.FragCount)}
		d.entries[m.PacketID] = e
	} else if e.frags[m.FragID] != nil {
		// Duplicate fragment, the one we already have wins
		return nil
	}
	e.frags[m.FragID] = m
	e.count++
	e.size += len(m.Data)
	e.last = now

	if e.size > defraggerMaxMessageSize {
		// Nothing legitimate can reassemble into this, so drop the group right
		// away instead of letting it hold memory until the timeout.
		delete(d.entries, m.PacketID)
		return nil
	}
	if int(e.count) != len(e.frags) {
		return nil
	}

	// All fragments received, assemble
	delete(d.entries, m.PacketID)
	data := make([]byte, e.size)
	off := 0
	for _, frag := range e.frags {
		off += copy(data[off:], frag.Data)
	}
	m.Data = data
	m.FragID = 0
	m.FragCount = 1
	return m
}

// sweep drops groups that have gone quiet for longer than the timeout.
// It runs on the receive path instead of a timer so that a Defragger owns no
// goroutine and needs no shutdown; a Defragger that stops being fed is itself
// dropped along with its session.
func (d *Defragger) sweep(now time.Time) {
	for id, e := range d.entries {
		if now.Sub(e.last) > d.timeout {
			delete(d.entries, id)
		}
	}
}

// evictOldest makes room by dropping the least recently updated group.
// That group is the one whose missing fragments are least likely to still be
// on their way. Dropping the newest group instead would be self-defeating:
// once the table is full, every newly started group would be killed on arrival
// and nothing would ever complete again.
func (d *Defragger) evictOldest() {
	var oldestID uint16
	var oldest time.Time
	found := false
	for id, e := range d.entries {
		if !found || e.last.Before(oldest) {
			oldestID, oldest, found = id, e.last, true
		}
	}
	if found {
		delete(d.entries, oldestID)
	}
}
