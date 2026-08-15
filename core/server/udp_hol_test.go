package server

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/protocol"
)

// TestUDPSessionManagerNoHeadOfLineBlocking pins the reason each session owns a
// send queue and a goroutine.
//
// Every session on a QUIC connection is fed from one receive loop. Writing to
// the target from that loop makes the write a shared resource: a single session
// whose destination is slow to accept a write -- a host that is not answering,
// a full socket buffer, a route being resolved -- stops every other session on
// the connection, and what gets dropped is not that session's traffic but
// everyone else's, in quic-go's receive queue, silently.
//
// The test holds one session's WriteTo open and requires an unrelated session
// to still get its packet through. Feeding synchronously from the receive loop
// fails it by timeout.
func TestUDPSessionManagerNoHeadOfLineBlocking(t *testing.T) {
	io := newMockUDPIO(t)
	eventLogger := newMockUDPEventLogger(t)
	sm := newUDPSessionManager(io, eventLogger, nil, 10*time.Second)

	msgCh := make(chan *protocol.UDPMessage, 4)
	io.EXPECT().ReceiveMessage().RunAndReturn(func() (*protocol.UDPMessage, error) {
		m := <-msgCh
		if m == nil {
			return nil, errors.New("closed")
		}
		return m, nil
	})
	// Neither session's target ever replies, so no session sends anything back.
	blockedRead := make(chan struct{})
	readFunc := func(b []byte) (int, string, error) {
		<-blockedRead
		return 0, "", errors.New("closed")
	}

	slowMsg := &protocol.UDPMessage{
		SessionID: 1, FragCount: 1, Addr: "slow.example:9000", Data: []byte("slow"),
	}
	fastMsg := &protocol.UDPMessage{
		SessionID: 2, FragCount: 1, Addr: "fast.example:9000", Data: []byte("fast"),
	}

	// The slow session's write is held open until the test releases it.
	releaseSlow := make(chan struct{})
	slowEntered := make(chan struct{})
	slowConn := newMockUDPConn(t)
	slowConn.EXPECT().WriteTo(slowMsg.Data, slowMsg.Addr).RunAndReturn(
		func([]byte, string) (int, error) {
			close(slowEntered)
			<-releaseSlow
			return len(slowMsg.Data), nil
		}).Once()
	slowConn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(readFunc).Maybe()
	slowConn.EXPECT().Close().Return(nil).Maybe()

	fastWrote := make(chan struct{})
	fastConn := newMockUDPConn(t)
	fastConn.EXPECT().WriteTo(fastMsg.Data, fastMsg.Addr).RunAndReturn(
		func([]byte, string) (int, error) {
			close(fastWrote)
			return len(fastMsg.Data), nil
		}).Once()
	fastConn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(readFunc).Maybe()
	fastConn.EXPECT().Close().Return(nil).Maybe()

	eventLogger.EXPECT().New(slowMsg.SessionID, slowMsg.Addr).Return().Once()
	eventLogger.EXPECT().New(fastMsg.SessionID, fastMsg.Addr).Return().Once()
	eventLogger.EXPECT().Close(mock.Anything, mock.Anything).Return().Maybe()
	io.EXPECT().Hook(slowMsg.Data, &slowMsg.Addr).Return(nil).Once()
	io.EXPECT().Hook(fastMsg.Data, &fastMsg.Addr).Return(nil).Once()
	io.EXPECT().UDP(slowMsg.Addr).Return(slowConn, nil).Once()
	io.EXPECT().UDP(fastMsg.Addr).Return(fastConn, nil).Once()

	go sm.Run()

	msgCh <- slowMsg
	select {
	case <-slowEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("slow session never reached its write")
	}

	// The slow session is now parked inside WriteTo. An unrelated session must
	// still be served.
	msgCh <- fastMsg
	select {
	case <-fastWrote:
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled session blocked an unrelated one from being served")
	}

	close(releaseSlow)
	close(blockedRead)
	close(msgCh)
}

// TestUDPSessionQueueFullCounted pins that an over-full session queue drops and
// says so. The drop itself is correct for a datagram; being unable to tell it
// happened is what makes a half-working relay look idle.
func TestUDPSessionQueueFullCounted(t *testing.T) {
	stats := &Stats{}
	// Park the sendLoop in its dial so nothing drains the queue. Closing done
	// by hand would bypass the closed flag that makes CloseWithErr idempotent.
	dialing := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var once sync.Once
	e := newUDPSessionEntry(7, newMockUDPIO(t), stats,
		func(string, []byte) (UDPConn, string, error) {
			once.Do(func() { close(dialing) })
			<-release
			return nil, "", errors.New("released")
		},
		func(error) {})

	msg := &protocol.UDPMessage{SessionID: 7, FragCount: 1, Addr: "x:1", Data: []byte("d")}
	e.Enqueue(msg)
	<-dialing // the loop now holds one message and is stuck

	const overfill = 64
	for i := 0; i < sessionSendQueueLen+overfill; i++ {
		e.Enqueue(msg)
	}
	// The queue holds sessionSendQueueLen; everything past that must be counted
	// rather than silently discarded or blocked.
	assert.GreaterOrEqual(t, stats.UDPSessionQueueFull.Load(), uint64(overfill),
		"messages past the queue limit went somewhere untracked")
}
