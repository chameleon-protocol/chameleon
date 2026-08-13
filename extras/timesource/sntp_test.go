package timesource

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ntpBytes is the inverse of ntpTime, used to build server replies.
func ntpBytes(t time.Time) []byte {
	sec := t.Unix() + ntpEpochOffset
	frac := (int64(t.Nanosecond()) << 32) / int64(time.Second)
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], uint32(sec))
	binary.BigEndian.PutUint32(b[4:8], uint32(frac))
	return b
}

// reply builds a well-formed server response to req, claiming that the server
// received and sent it at serverTime.
func reply(req []byte, serverTime time.Time) []byte {
	resp := make([]byte, ntpPacketSize)
	resp[0] = 0x24 // LI = 0, VN = 4, Mode = 4 (server)
	resp[1] = 2    // stratum
	copy(resp[24:32], req[40:48])
	copy(resp[32:40], ntpBytes(serverTime))
	copy(resp[40:48], ntpBytes(serverTime))
	return resp
}

// fakeExchanger answers each server address with a canned handler.
type fakeExchanger struct {
	handlers map[string]func(req []byte) ([]byte, error)
	asked    []string
}

func (f *fakeExchanger) Exchange(ctx context.Context, server string, req []byte) ([]byte, error) {
	f.asked = append(f.asked, server)
	h, ok := f.handlers[server]
	if !ok {
		return nil, errors.New("no route to host")
	}
	return h(req)
}

// newTestClient returns a client whose local clock is stuck at the Unix epoch,
// the situation this package exists for.
func newTestClient(servers []string, ex Exchanger) (*SNTPClient, *time.Time) {
	local := time.Unix(0, 0).UTC()
	c := &SNTPClient{
		Servers:  servers,
		Exchange: ex,
		rand:     bytes.NewReader(bytes.Repeat([]byte{0xAB}, 64)),
		now:      func() time.Time { return local },
	}
	return c, &local
}

func TestSNTPQuery(t *testing.T) {
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){
		"a:123": func(req []byte) ([]byte, error) { return reply(req, trueTime), nil },
	}}
	c, _ := newTestClient([]string{"a:123"}, ex)

	res, err := c.Query(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "a:123", res.Server)
	assert.WithinDuration(t, trueTime, res.Time, time.Second)
	// The local clock is at the epoch, so the offset is the whole gap.
	assert.WithinDuration(t, trueTime, time.Unix(0, 0).UTC().Add(res.Offset), time.Second)
}

func TestSNTPQueryRejectsBadReplies(t *testing.T) {
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	tests := []struct {
		name    string
		mangle  func(req, resp []byte) []byte
		wantErr error
	}{
		{"short packet", func(req, resp []byte) []byte { return resp[:40] }, errShortPacket},
		{"leap indicator unsynchronized", func(req, resp []byte) []byte {
			resp[0] |= 0xC0
			return resp
		}, errUnsynchronized},
		{"not server mode", func(req, resp []byte) []byte {
			resp[0] = resp[0]&^0x07 | 3
			return resp
		}, errNotServerMode},
		{"kiss of death", func(req, resp []byte) []byte {
			resp[1] = 0
			return resp
		}, errBadStratum},
		{"stratum out of range", func(req, resp []byte) []byte {
			resp[1] = 16
			return resp
		}, errBadStratum},
		{"nonce not echoed", func(req, resp []byte) []byte {
			resp[24] ^= 0xFF
			return resp
		}, errNonceMismatch},
		{"zero transmit timestamp", func(req, resp []byte) []byte {
			copy(resp[40:48], make([]byte, 8))
			return resp
		}, errZeroTimestamp},
		{"server received after it sent", func(req, resp []byte) []byte {
			copy(resp[32:40], ntpBytes(trueTime.Add(time.Minute)))
			return resp
		}, errBadRoundTrip},
		{"server took longer than the round trip", func(req, resp []byte) []byte {
			copy(resp[32:40], ntpBytes(trueTime.Add(-time.Minute)))
			return resp
		}, errBadRoundTrip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){
				"bad:123": func(req []byte) ([]byte, error) { return tt.mangle(req, reply(req, trueTime)), nil },
			}}
			c, _ := newTestClient([]string{"bad:123"}, ex)

			_, err := c.Query(context.Background())
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestSNTPQueryFallsThroughToNextServer(t *testing.T) {
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){
		"unreachable:123": func(req []byte) ([]byte, error) { return nil, errors.New("timeout") },
		"lying:123": func(req []byte) ([]byte, error) {
			resp := reply(req, trueTime)
			resp[1] = 0 // kiss of death
			return resp, nil
		},
		"good:123": func(req []byte) ([]byte, error) { return reply(req, trueTime), nil },
	}}
	c, _ := newTestClient([]string{"unreachable:123", "lying:123", "good:123"}, ex)

	res, err := c.Query(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "good:123", res.Server)
	assert.WithinDuration(t, trueTime, res.Time, time.Second)
}

func TestSNTPQueryTakesMedian(t *testing.T) {
	trueTime := time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)
	ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){
		"early:123":  func(req []byte) ([]byte, error) { return reply(req, trueTime.Add(-8*time.Hour)), nil },
		"honest:123": func(req []byte) ([]byte, error) { return reply(req, trueTime), nil },
		"late:123":   func(req []byte) ([]byte, error) { return reply(req, trueTime.Add(8*time.Hour)), nil },
	}}
	c, _ := newTestClient([]string{"early:123", "honest:123", "late:123"}, ex)

	res, err := c.Query(context.Background())
	require.NoError(t, err)
	assert.WithinDuration(t, trueTime, res.Time, time.Second)
}

func TestSNTPQueryAllServersFail(t *testing.T) {
	ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){}}
	c, _ := newTestClient([]string{"a:123", "b:123"}, ex)

	_, err := c.Query(context.Background())
	require.Error(t, err)
	assert.Equal(t, []string{"a:123", "b:123"}, ex.asked)

	c.Servers = nil
	_, err = c.Query(context.Background())
	assert.ErrorIs(t, err, ErrNoServers)
}

func TestSNTPQueryHonorsCanceledContext(t *testing.T) {
	ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){
		"a:123": func(req []byte) ([]byte, error) { return reply(req, time.Now()), nil },
	}}
	c, _ := newTestClient([]string{"a:123"}, ex)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Query(ctx)
	require.Error(t, err)
	assert.Empty(t, ex.asked)
}

// Timestamps past 2036-02-07 wrap into NTP era 1; a client that ignores the
// era reads them as 1900 and would refuse to work at all.
func TestNTPTimeEraRollover(t *testing.T) {
	for _, want := range []time.Time{
		time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC),
		time.Date(2036, 2, 8, 0, 0, 0, 0, time.UTC),
		time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		assert.WithinDuration(t, want, ntpTime(ntpBytes(want)), time.Millisecond)
	}
}

func TestSNTPRequestIsWellFormed(t *testing.T) {
	var got []byte
	ex := &fakeExchanger{handlers: map[string]func([]byte) ([]byte, error){
		"a:123": func(req []byte) ([]byte, error) {
			got = append([]byte(nil), req...)
			return reply(req, time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)), nil
		},
	}}
	c, _ := newTestClient([]string{"a:123"}, ex)
	_, err := c.Query(context.Background())
	require.NoError(t, err)

	require.Len(t, got, ntpPacketSize)
	assert.EqualValues(t, 0, got[0]>>6, "leap indicator")
	assert.EqualValues(t, 4, got[0]>>3&0x07, "version")
	assert.EqualValues(t, 3, got[0]&0x07, "mode")
	// The transmit timestamp must carry the random nonce, not the (bogus)
	// local time, otherwise it is guessable by an off-path spoofer.
	assert.Equal(t, bytes.Repeat([]byte{0xAB}, 8), got[40:48])
}
