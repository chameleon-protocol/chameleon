package server

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/chameleon-protocol/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/goleak"

	"github.com/chameleon-protocol/chameleon/core/v2/internal/frag"
	"github.com/chameleon-protocol/chameleon/core/v2/internal/protocol"
)

func TestUDPSessionManager(t *testing.T) {
	io := newMockUDPIO(t)
	eventLogger := newMockUDPEventLogger(t)
	sm := newUDPSessionManager(io, eventLogger, nil, 2*time.Second)

	msgCh := make(chan *protocol.UDPMessage, 4)
	io.EXPECT().ReceiveMessage().RunAndReturn(func() (*protocol.UDPMessage, error) {
		m := <-msgCh
		if m == nil {
			return nil, errors.New("closed")
		}
		return m, nil
	})

	go sm.Run()

	udpReadFunc := func(addr string, ch chan []byte, b []byte) (int, string, error) {
		bs := <-ch
		if bs == nil {
			return 0, "", errors.New("closed")
		}
		n := copy(b, bs)
		return n, addr, nil
	}

	// Test normal session creation & timeout
	msg1 := &protocol.UDPMessage{
		SessionID: 1234,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "address1.com:9000",
		Data:      []byte("hello"),
	}
	eventLogger.EXPECT().New(msg1.SessionID, msg1.Addr).Return().Once()
	udpConn1 := newMockUDPConn(t)
	udpConn1Ch := make(chan []byte, 1)
	io.EXPECT().Hook(msg1.Data, &msg1.Addr).Return(nil).Once()
	io.EXPECT().UDP(msg1.Addr).Return(udpConn1, nil).Once()
	udpConn1.EXPECT().WriteTo(msg1.Data, msg1.Addr).Return(5, nil).Once()
	udpConn1.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, string, error) {
		return udpReadFunc(msg1.Addr, udpConn1Ch, b)
	})
	io.EXPECT().SendMessage(mock.Anything, &protocol.UDPMessage{
		SessionID: msg1.SessionID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg1.Addr,
		Data:      []byte("hi back"),
	}).Return(nil).Once()
	msgCh <- msg1
	udpConn1Ch <- []byte("hi back")

	msg2data := []byte("how are you doing?")
	msg2_1 := &protocol.UDPMessage{
		SessionID: 5678,
		PacketID:  0,
		FragID:    0,
		FragCount: 2,
		Addr:      "address2.net:12450",
		Data:      msg2data[:6],
	}
	msg2_2 := &protocol.UDPMessage{
		SessionID: 5678,
		PacketID:  0,
		FragID:    1,
		FragCount: 2,
		Addr:      "address2.net:12450",
		Data:      msg2data[6:],
	}

	eventLogger.EXPECT().New(msg2_1.SessionID, msg2_1.Addr).Return().Once()
	udpConn2 := newMockUDPConn(t)
	udpConn2Ch := make(chan []byte, 1)
	// On fragmentation, make sure hook gets the whole message
	io.EXPECT().Hook(msg2data, &msg2_1.Addr).Return(nil).Once()
	io.EXPECT().UDP(msg2_1.Addr).Return(udpConn2, nil).Once()
	udpConn2.EXPECT().WriteTo(msg2data, msg2_1.Addr).Return(11, nil).Once()
	udpConn2.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, string, error) {
		return udpReadFunc(msg2_1.Addr, udpConn2Ch, b)
	})
	io.EXPECT().SendMessage(mock.Anything, &protocol.UDPMessage{
		SessionID: msg2_1.SessionID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg2_1.Addr,
		Data:      []byte("im fine"),
	}).Return(nil).Once()
	msgCh <- msg2_1
	msgCh <- msg2_2
	udpConn2Ch <- []byte("im fine")

	msg3 := &protocol.UDPMessage{
		SessionID: 1234,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "address1.com:9000",
		Data:      []byte("who are you?"),
	}
	udpConn1.EXPECT().WriteTo(msg3.Data, msg3.Addr).Return(12, nil).Once()
	io.EXPECT().SendMessage(mock.Anything, &protocol.UDPMessage{
		SessionID: msg3.SessionID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg3.Addr,
		Data:      []byte("im your father"),
	}).Return(nil).Once()
	msgCh <- msg3
	udpConn1Ch <- []byte("im your father")

	// Make sure timeout works (connections closed & close events emitted)
	udpConn1.EXPECT().Close().RunAndReturn(func() error {
		close(udpConn1Ch)
		return nil
	}).Once()
	udpConn2.EXPECT().Close().RunAndReturn(func() error {
		close(udpConn2Ch)
		return nil
	}).Once()
	eventLogger.EXPECT().Close(msg1.SessionID, nil).Once()
	eventLogger.EXPECT().Close(msg2_1.SessionID, nil).Once()

	time.Sleep(3 * time.Second) // Wait for timeout
	mock.AssertExpectationsForObjects(t, io, eventLogger, udpConn1, udpConn2)

	// Test UDP connection close error propagation
	errUDPClosed := errors.New("UDP connection closed")
	msg4 := &protocol.UDPMessage{
		SessionID: 666,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "oh-no.com:27015",
		Data:      []byte("dont say bye"),
	}
	eventLogger.EXPECT().New(msg4.SessionID, msg4.Addr).Return().Once()
	udpConn4 := newMockUDPConn(t)
	io.EXPECT().Hook(msg4.Data, &msg4.Addr).Return(nil).Once()
	io.EXPECT().UDP(msg4.Addr).Return(udpConn4, nil).Once()
	udpConn4.EXPECT().WriteTo(msg4.Data, msg4.Addr).Return(12, nil).Once()
	udpConn4.EXPECT().ReadFrom(mock.Anything).Return(0, "", errUDPClosed).Once()
	udpConn4.EXPECT().Close().Return(nil).Once()
	eventLogger.EXPECT().Close(msg4.SessionID, errUDPClosed).Once()
	msgCh <- msg4

	time.Sleep(1 * time.Second)
	mock.AssertExpectationsForObjects(t, io, eventLogger, udpConn4)

	// Test UDP connection creation error propagation
	errUDPIO := errors.New("UDP IO error")
	msg5 := &protocol.UDPMessage{
		SessionID: 777,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "callmemaybe.com:15353",
		Data:      []byte("babe i miss you"),
	}
	eventLogger.EXPECT().New(msg5.SessionID, msg5.Addr).Return().Once()
	io.EXPECT().Hook(msg5.Data, &msg5.Addr).Return(nil).Once()
	io.EXPECT().UDP(msg5.Addr).Return(nil, errUDPIO).Once()
	eventLogger.EXPECT().Close(msg5.SessionID, errUDPIO).Once()
	msgCh <- msg5

	time.Sleep(1 * time.Second)
	mock.AssertExpectationsForObjects(t, io, eventLogger)

	// Leak checks
	close(msgCh)                // This will return error from ReceiveMessage(), should stop the session manager
	time.Sleep(1 * time.Second) // Wait one more second just to be sure
	assert.Zero(t, sm.Count(), "session count should be 0")
	goleak.VerifyNone(t)
}

// TestUDPSessionManagerLargePayload makes sure that payloads too large for a
// single datagram get to the client in one piece, including the band right
// below MaxUDPSize, where the message no longer fits in the send buffer once
// its header is taken into account.
func TestUDPSessionManagerLargePayload(t *testing.T) {
	const maxDatagramPayloadSize = 1200

	for _, payloadLen := range []int{1200, 4077, 4078, 4095, protocol.MaxUDPSize} {
		t.Run(strconv.Itoa(payloadLen), func(t *testing.T) {
			io := newMockUDPIO(t)
			eventLogger := newMockUDPEventLogger(t)
			sm := newUDPSessionManager(io, eventLogger, nil, 10*time.Second)

			msgCh := make(chan *protocol.UDPMessage, 1)
			io.EXPECT().ReceiveMessage().RunAndReturn(func() (*protocol.UDPMessage, error) {
				m := <-msgCh
				if m == nil {
					return nil, errors.New("closed")
				}
				return m, nil
			})
			// Emulate udpIOImpl.SendMessage on a QUIC connection that only
			// accepts datagrams up to maxDatagramPayloadSize.
			dgramCh := make(chan []byte, 16)
			io.EXPECT().SendMessage(mock.Anything, mock.Anything).RunAndReturn(func(buf []byte, msg *protocol.UDPMessage) error {
				wire := msg.SerializeTo(buf)
				if len(wire) > maxDatagramPayloadSize {
					return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: maxDatagramPayloadSize}
				}
				dgramCh <- append([]byte(nil), wire...)
				return nil
			})

			go sm.Run()

			initMsg := &protocol.UDPMessage{
				SessionID: 88,
				PacketID:  0,
				FragID:    0,
				FragCount: 1,
				Addr:      "large.payload.test:4433",
				Data:      []byte("hello"),
			}
			udpConn := newMockUDPConn(t)
			connCh := make(chan []byte, 1)
			eventLogger.EXPECT().New(initMsg.SessionID, initMsg.Addr).Return().Once()
			io.EXPECT().Hook(initMsg.Data, &initMsg.Addr).Return(nil).Once()
			io.EXPECT().UDP(initMsg.Addr).Return(udpConn, nil).Once()
			udpConn.EXPECT().WriteTo(initMsg.Data, initMsg.Addr).Return(len(initMsg.Data), nil).Once()
			udpConn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, string, error) {
				bs := <-connCh
				if bs == nil {
					return 0, "", errors.New("closed")
				}
				return copy(b, bs), initMsg.Addr, nil
			})
			msgCh <- initMsg

			payload := make([]byte, payloadLen)
			for i := range payload {
				payload[i] = byte(i)
			}
			connCh <- payload

			// Reassemble what the server put on the wire, like a client would.
			var d frag.Defragger
			var got *protocol.UDPMessage
			for got == nil {
				select {
				case dgram := <-dgramCh:
					msg, err := protocol.ParseUDPMessage(dgram)
					if !assert.NoError(t, err) {
						return
					}
					got = d.Feed(msg)
				case <-time.After(5 * time.Second):
					t.Fatal("timeout waiting for the payload")
				}
			}
			assert.Equal(t, payload, got.Data)
			assert.Equal(t, initMsg.Addr, got.Addr)

			udpConn.EXPECT().Close().RunAndReturn(func() error {
				close(connCh)
				return nil
			}).Once()
			eventLogger.EXPECT().Close(initMsg.SessionID, nil).Once()
			close(msgCh)
			assert.Eventually(t, func() bool { return sm.Count() == 0 }, 5*time.Second, 50*time.Millisecond)
			mock.AssertExpectationsForObjects(t, io, eventLogger, udpConn)
		})
	}

	goleak.VerifyNone(t)
}
