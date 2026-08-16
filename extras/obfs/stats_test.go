package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// The whole point of splitting the counters is that an operator can tell the
// three failures apart, so each case has to move its own counter and leave the
// other two alone.
func TestSalamanderV2CountsRejectionsSeparately(t *testing.T) {
	const payloadStr = "a QUIC datagram would go here"
	payload := []byte(payloadStr)

	t.Run("aead", func(t *testing.T) {
		client, _ := pair(t, "the_right_password", "", nil)
		_, server := pair(t, "the_wrong_password", "", nil)

		wire := make([]byte, len(payload)+smV2Overhead)
		n := client.Obfuscate(payload, wire)
		if got := server.Deobfuscate(wire[:n], make([]byte, 2048)); got != 0 {
			t.Fatalf("a packet sealed under another password decoded to %d bytes", got)
		}

		s := server.Stats().Snapshot()
		if s.AEADFailed != 1 {
			t.Errorf("AEADFailed = %d, want 1", s.AEADFailed)
		}
		if s.ClockSkew != 0 || s.Replayed != 0 || s.Malformed != 0 {
			t.Errorf("a wrong password moved another counter: %+v", s)
		}
	})

	t.Run("clock skew", func(t *testing.T) {
		now := time.Now()
		client, server := pair(t, "a_reasonable_password", "", &now)

		wire := make([]byte, len(payload)+smV2Overhead)
		n := client.Obfuscate(payload, wire)
		// The receiver's clock jumps forward past the window while the packet
		// is in flight, which is what an unsynchronized node looks like.
		now = now.Add(smV2MaxSkew + 10*time.Second)
		if got := server.Deobfuscate(wire[:n], make([]byte, 2048)); got != 0 {
			t.Fatalf("a stale packet decoded to %d bytes", got)
		}

		s := server.Stats().Snapshot()
		if s.ClockSkew != 1 {
			t.Errorf("ClockSkew = %d, want 1", s.ClockSkew)
		}
		if s.AEADFailed != 0 || s.Replayed != 0 || s.Malformed != 0 {
			t.Errorf("a clock problem moved another counter: %+v", s)
		}
		// The peer's timestamp is older than ours, so the reported skew is
		// negative and roughly the size of the jump.
		if want := -(smV2MaxSkew + 10*time.Second); s.LastSkew < want-2*time.Second || s.LastSkew > want+2*time.Second {
			t.Errorf("LastSkew = %v, want about %v", s.LastSkew, want)
		}
	})

	t.Run("replay", func(t *testing.T) {
		client, server := pair(t, "a_reasonable_password", "", nil)

		wire := make([]byte, len(payload)+smV2Overhead)
		n := client.Obfuscate(payload, wire)
		recorded := bytes.Clone(wire[:n])
		out := make([]byte, 2048)
		if got := server.Deobfuscate(bytes.Clone(recorded), out); got != len(payload) {
			t.Fatalf("first delivery should succeed, got %d", got)
		}
		if got := server.Deobfuscate(bytes.Clone(recorded), out); got != 0 {
			t.Fatalf("replay decoded to %d bytes", got)
		}

		s := server.Stats().Snapshot()
		if s.Replayed != 1 {
			t.Errorf("Replayed = %d, want 1", s.Replayed)
		}
		if s.AEADFailed != 0 || s.ClockSkew != 0 || s.Malformed != 0 {
			t.Errorf("a replay moved another counter: %+v", s)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		_, server := pair(t, "a_reasonable_password", "", nil)
		if got := server.Deobfuscate(make([]byte, smV2MinLen-1), make([]byte, 2048)); got != 0 {
			t.Fatalf("a runt packet decoded to %d bytes", got)
		}

		s := server.Stats().Snapshot()
		if s.Malformed != 1 {
			t.Errorf("Malformed = %d, want 1", s.Malformed)
		}
		if s.AEADFailed != 0 || s.ClockSkew != 0 || s.Replayed != 0 {
			t.Errorf("a runt packet moved another counter: %+v", s)
		}
	})

	t.Run("success moves nothing", func(t *testing.T) {
		client, server := pair(t, "a_reasonable_password", "", nil)
		wire := make([]byte, len(payload)+smV2Overhead)
		n := client.Obfuscate(payload, wire)
		if got := server.Deobfuscate(wire[:n], make([]byte, 2048)); got != len(payload) {
			t.Fatalf("round trip returned %d, want %d", got, len(payload))
		}
		if s := server.Stats().Snapshot(); s != (StatsSnapshot{}) {
			t.Errorf("a good packet was counted as a rejection: %+v", s)
		}
	})
}

// A clock hint is only useful if it names the direction and the magnitude; a
// bare "timestamp rejected" leaves the operator exactly where they started.
func TestClockSkewHint(t *testing.T) {
	var s Stats
	if hint := s.Snapshot().ClockSkewHint(); hint != "" {
		t.Errorf("no rejections should produce no hint, got %q", hint)
	}

	s.recordSkew(1000, 955)
	hint := s.Snapshot().ClockSkewHint()
	if !strings.Contains(hint, "45s") {
		t.Errorf("hint should name the size of the skew, got %q", hint)
	}
	if !strings.Contains(hint, "ahead") {
		t.Errorf("a peer 45s in the future should be reported as ahead, got %q", hint)
	}

	s.recordSkew(955, 1000)
	if hint := s.Snapshot().ClockSkewHint(); !strings.Contains(hint, "behind") {
		t.Errorf("a peer 45s in the past should be reported as behind, got %q", hint)
	}
}

// junkConn hands ReadFrom a fixed number of packets that cannot possibly
// deobfuscate, then reports the socket closed.
type junkConn struct {
	remaining int
}

func (c *junkConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.remaining == 0 {
		return 0, nil, io.EOF
	}
	c.remaining--
	return copy(p, make([]byte, 64)), &net.UDPAddr{}, nil
}

func (c *junkConn) WriteTo([]byte, net.Addr) (int, error) { return 0, nil }
func (c *junkConn) Close() error                          { return nil }
func (c *junkConn) LocalAddr() net.Addr                   { return &net.UDPAddr{} }
func (c *junkConn) SetDeadline(time.Time) error           { return nil }
func (c *junkConn) SetReadDeadline(time.Time) error       { return nil }
func (c *junkConn) SetWriteDeadline(time.Time) error      { return nil }

// ReadFrom silently loops on a packet it cannot decode, so the count of those
// loops is the only evidence the traffic ever arrived.
func TestPacketConnCountsSilentDrops(t *testing.T) {
	ob, err := NewSalamanderV2([]byte("a_reasonable_password"), "", RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	conn := wrapPacketConn(&junkConn{remaining: 5}, ob, "test")

	if _, _, err := conn.ReadFrom(make([]byte, 2048)); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadFrom should have looped over the junk and reported the close, got %v", err)
	}

	stats := StatsOf(conn)
	if stats == nil {
		t.Fatal("StatsOf returned nil for a wrapped conn")
	}
	s := stats.Snapshot()
	if s.Dropped != 5 {
		t.Errorf("Dropped = %d, want 5", s.Dropped)
	}
	// The connection and the obfuscator have to share one Stats, or the total
	// and the breakdown describe different populations.
	if s.AEADFailed != 5 {
		t.Errorf("AEADFailed = %d, want 5 - the classes should add up to Dropped", s.AEADFailed)
	}
}

func TestStatsOfPlainConn(t *testing.T) {
	if s := StatsOf(fakePlainConn{}); s != nil {
		t.Errorf("StatsOf on an unwrapped conn returned %v, want nil", s)
	}
}
