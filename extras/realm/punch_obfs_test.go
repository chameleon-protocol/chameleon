package realm

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chameleon-protocol/chameleon/extras/v2/obfs"
)

// Punch packets and obfuscated data packets share one socket on a server, with
// the punch demux underneath the obfuscator. Two things about that layering are
// worth pinning rather than reasoning about:
//
//   - Retransmitted punch packets keep being delivered. Salamander v2 keeps a
//     replay set and a boot barrier, and a punch packet that went through it
//     would be judged by both. It does not: the demux sits below the
//     obfuscator and takes punch packets out of the stream before it sees them.
//   - Data packets still reach the obfuscator with the demux in the way.
func TestPunchAndObfsShareTheSocket(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	punchConn, err := NewPunchPacketConn(server, testMask, 8)
	require.NoError(t, err)
	obfsServer, err := obfs.WrapPacketConnSalamanderV2(punchConn, []byte("obfs-password"), "test", obfs.RoleServer)
	require.NoError(t, err)
	obfsPeer, err := obfs.WrapPacketConnSalamanderV2(peer, []byte("obfs-password"), "test", obfs.RoleClient)
	require.NoError(t, err)

	meta := testPunchMetadata()
	events, err := punchConn.AddPunchAttempt("attempt-1", meta)
	require.NoError(t, err)

	type read struct {
		payload []byte
		err     error
	}
	reads := make(chan read, 1)
	go func() {
		buf := make([]byte, 1500)
		n, _, err := obfsServer.ReadFrom(buf)
		reads <- read{payload: append([]byte(nil), buf[:n]...), err: err}
	}()

	// The same attempt, over and over, as a punch that keeps its NAT mapping
	// alive does.
	const retransmits = 8
	for range retransmits {
		packet, err := EncodePunchPacket(PunchPacketHello, meta, testMask)
		require.NoError(t, err)
		_, err = peer.WriteTo(packet, server.LocalAddr())
		require.NoError(t, err)
	}
	for i := range retransmits {
		select {
		case ev := <-events:
			assert.Equal(t, PunchPacketHello, ev.Packet.Type)
		case <-time.After(2 * time.Second):
			t.Fatalf("retransmit %d of %d was never delivered", i+1, retransmits)
		}
	}

	payload := []byte("data packet that belongs to the obfuscator")
	_, err = obfsPeer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)
	select {
	case got := <-reads:
		require.NoError(t, got.err)
		assert.Equal(t, payload, got.payload)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the data packet")
	}
}

// The server stack samples lengths as they go on the wire, which means below
// the obfuscator: a punch packet padded to the length of an obfuscator's
// plaintext would be short by exactly the obfuscator's overhead, on every
// packet, which is the beacon a fixed target would have been.
func TestPunchLengthSampleIsThePostObfsLength(t *testing.T) {
	rec := &recordingPacketConn{addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
	punchConn, err := NewPunchPacketConn(rec, testMask, 1)
	require.NoError(t, err)
	obfsServer, err := obfs.WrapPacketConnSalamanderV2(punchConn, []byte("obfs-password"), "test", obfs.RoleServer)
	require.NoError(t, err)

	const payloadLen = 1200
	_, err = obfsServer.WriteTo(make([]byte, payloadLen), rec.addr)
	require.NoError(t, err)

	sampled, ok := punchConn.lengths.sample()
	require.True(t, ok)
	written := rec.written()
	require.Len(t, written, 1)
	assert.Equal(t, written[0], sampled)
	assert.Greater(t, sampled, payloadLen, "the sample is a plaintext length, not a wire length")
}
