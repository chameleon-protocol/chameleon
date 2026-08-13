package frag

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/protocol"
)

func TestFragUDPMessage(t *testing.T) {
	type args struct {
		m       *protocol.UDPMessage
		maxSize int
	}
	tests := []struct {
		name string
		args args
		want []protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
				100,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
			},
		},
		{
			"2 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
				20,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("hel"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("lo"),
				},
			},
		},
		{
			"4 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("abcdefgh"),
				},
				19,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("ab"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("cd"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    2,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("ef"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    3,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("gh"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FragUDPMessage(tt.args.m, tt.args.maxSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FragUDPMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func fragMsg(pktID uint16, fragID, fragCount uint8, data string) *protocol.UDPMessage {
	return &protocol.UDPMessage{
		SessionID: 123,
		PacketID:  pktID,
		FragID:    fragID,
		FragCount: fragCount,
		Addr:      "test:123",
		Data:      []byte(data),
	}
}

// feedNil feeds a fragment that must not complete a message.
func feedNil(t *testing.T, d *Defragger, m *protocol.UDPMessage) {
	t.Helper()
	pktID, fragID := m.PacketID, m.FragID
	if got := d.Feed(m); got != nil {
		t.Fatalf("Feed(packet %d, frag %d) = %q, want nil", pktID, fragID, got.Data)
	}
}

// feedDone feeds a fragment that must complete a message carrying want.
func feedDone(t *testing.T, d *Defragger, m *protocol.UDPMessage, want string) {
	t.Helper()
	pktID, fragID := m.PacketID, m.FragID
	got := d.Feed(m)
	if got == nil {
		t.Fatalf("Feed(packet %d, frag %d) = nil, want %q", pktID, fragID, want)
	}
	if string(got.Data) != want {
		t.Errorf("Feed(packet %d, frag %d) = %q, want %q", pktID, fragID, got.Data, want)
	}
	if got.FragID != 0 || got.FragCount != 1 {
		t.Errorf("reassembled message still marked as fragment %d/%d", got.FragID, got.FragCount)
	}
}

func TestDefraggerNoFrag(t *testing.T) {
	d := NewDefragger()
	m := fragMsg(0, 0, 1, "hello")
	if got := d.Feed(m); got != m {
		t.Errorf("Feed() = %v, want the message itself", got)
	}
	if len(d.entries) != 0 {
		t.Errorf("entries = %d, want 0: unfragmented messages must not be tracked", len(d.entries))
	}
}

func TestDefraggerReassemble(t *testing.T) {
	d := NewDefragger()
	feedNil(t, d, fragMsg(987, 0, 2, "hello "))
	feedDone(t, d, fragMsg(987, 1, 2, "moto"), "hello moto")

	// Fragments are placed by FragID, not by arrival order.
	feedNil(t, d, fragMsg(988, 2, 3, "27"))
	feedNil(t, d, fragMsg(988, 0, 3, "deco"))
	feedDone(t, d, fragMsg(988, 1, 3, "*"), "deco*27")

	if len(d.entries) != 0 {
		t.Errorf("entries = %d, want 0: completed groups must be released", len(d.entries))
	}
}

// TestDefraggerInterleaved covers what used to destroy both packets: two
// oversized packets in flight at once, whose fragments arrive interleaved.
func TestDefraggerInterleaved(t *testing.T) {
	d := NewDefragger()
	feedNil(t, d, fragMsg(100, 0, 2, "hello "))
	feedNil(t, d, fragMsg(200, 2, 3, "jo"))
	feedNil(t, d, fragMsg(300, 1, 2, "world"))
	feedNil(t, d, fragMsg(200, 0, 3, "shin"))
	feedDone(t, d, fragMsg(100, 1, 2, "moto"), "hello moto")
	feedDone(t, d, fragMsg(300, 0, 2, "hello "), "hello world")
	feedDone(t, d, fragMsg(200, 1, 3, "sekai"), "shinsekaijo")

	if len(d.entries) != 0 {
		t.Errorf("entries = %d, want 0: completed groups must be released", len(d.entries))
	}
}

func TestDefraggerDuplicateFragment(t *testing.T) {
	d := NewDefragger()
	feedNil(t, d, fragMsg(1, 0, 2, "hello "))
	feedNil(t, d, fragMsg(1, 0, 2, "byebye"))
	feedDone(t, d, fragMsg(1, 1, 2, "moto"), "hello moto")
}

func TestDefraggerFragCountMismatch(t *testing.T) {
	d := NewDefragger()
	feedNil(t, d, fragMsg(1, 0, 2, "hello "))
	// Same PacketID but a different fragment count: the fragments cannot
	// belong to the same message, so the old state is replaced, not mixed in.
	feedNil(t, d, fragMsg(1, 0, 3, "de"))
	feedNil(t, d, fragMsg(1, 1, 3, "co"))
	feedDone(t, d, fragMsg(1, 2, 3, "27"), "deco27")
}

func TestDefraggerInvalidFragID(t *testing.T) {
	d := NewDefragger()
	feedNil(t, d, fragMsg(1, 0, 2, "hello "))
	// FragID out of range: rejected without disturbing the group in progress.
	feedNil(t, d, fragMsg(1, 88, 2, "junk"))
	feedDone(t, d, fragMsg(1, 1, 2, "moto"), "hello moto")
}

func TestDefraggerTimeout(t *testing.T) {
	now := time.Unix(0, 0)
	d := &Defragger{timeout: time.Second, now: func() time.Time { return now }}

	// Within the timeout the group survives and completes.
	feedNil(t, d, fragMsg(1, 0, 2, "hello "))
	now = now.Add(900 * time.Millisecond)
	feedDone(t, d, fragMsg(1, 1, 2, "moto"), "hello moto")

	feedNil(t, d, fragMsg(2, 0, 2, "hello "))
	now = now.Add(2 * time.Second)
	// The first half has been swept, so a late second half starts a fresh
	// group instead of completing a stale one.
	feedNil(t, d, fragMsg(2, 1, 2, "moto"))
	if len(d.entries) != 1 {
		t.Errorf("entries = %d, want 1: expired groups must be swept", len(d.entries))
	}
}

func TestDefraggerMaxEntries(t *testing.T) {
	now := time.Unix(0, 0)
	d := &Defragger{maxEntries: 3, now: func() time.Time { return now }}

	for i := uint16(1); i <= 3; i++ {
		feedNil(t, d, fragMsg(i, 0, 2, "a"))
		now = now.Add(time.Millisecond)
	}
	// A fourth group has to push one out - the one waiting the longest.
	feedNil(t, d, fragMsg(4, 0, 2, "d"))
	if len(d.entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(d.entries))
	}

	// The groups that survived still reassemble.
	feedDone(t, d, fragMsg(2, 1, 2, "B"), "aB")
	feedDone(t, d, fragMsg(3, 1, 2, "C"), "aC")
	feedDone(t, d, fragMsg(4, 1, 2, "D"), "dD")

	// Group 1 is the one that was evicted.
	feedNil(t, d, fragMsg(1, 1, 2, "A"))
}

func TestDefraggerOversizedGroup(t *testing.T) {
	// Feeds a whole group of equally sized fragments and returns whatever the
	// last one produced, checking that nothing is left behind either way.
	const fragCount = uint8(255)
	feedGroup := func(t *testing.T, fragSize int) *protocol.UDPMessage {
		t.Helper()
		d := NewDefragger()
		payload := strings.Repeat("x", fragSize)
		var last *protocol.UDPMessage
		for i := uint8(0); i < fragCount; i++ {
			last = d.Feed(fragMsg(1, i, fragCount, payload))
		}
		if len(d.entries) != 0 {
			t.Errorf("entries = %d, want 0", len(d.entries))
		}
		return last
	}

	// Exactly at the limit: still a message anyone could have sent.
	if got := feedGroup(t, defraggerMaxMessageSize/int(fragCount)); got == nil {
		t.Error("group of exactly defraggerMaxMessageSize bytes was not reassembled")
	} else if len(got.Data) != defraggerMaxMessageSize {
		t.Errorf("reassembled %d bytes, want %d", len(got.Data), defraggerMaxMessageSize)
	}

	// One byte per fragment over: dropped, and its state along with it.
	if got := feedGroup(t, defraggerMaxMessageSize/int(fragCount)+1); got != nil {
		t.Errorf("oversized group reassembled into %d bytes, want dropped", len(got.Data))
	}
}

// A Defragger built as a bare struct literal must behave like NewDefragger's.
func TestDefraggerZeroValue(t *testing.T) {
	d := &Defragger{}
	feedNil(t, d, fragMsg(1, 0, 2, "hello "))
	feedDone(t, d, fragMsg(1, 1, 2, "moto"), "hello moto")
}
