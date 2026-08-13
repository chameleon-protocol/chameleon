// chameleon -- a censorship-resistant transport
// Copyright (C) 2026 The chameleon authors
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 3 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package obfs

import (
	"net"
	"testing"
)

// discardPacketConn stands in for a UDP socket. WriteTo does nothing, so what
// the benchmark measures is purely what the obfs wrapper adds around the send:
// obfuscation, buffer handling, and whatever serialization the wrapper imposes.
type discardPacketConn struct {
	net.PacketConn
}

func (discardPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (discardPacketConn) Close() error                              { return nil }
func (discardPacketConn) LocalAddr() net.Addr                       { return nil }

// BenchmarkWriteToParallel is the one that matters. quic-go runs one sendQueue
// goroutine per connection, so a server with N clients has N goroutines calling
// WriteTo at once. If the wrapper serializes them, this is where it shows.
func BenchmarkWriteToParallel(b *testing.B) {
	ob, err := newSalamanderObfuscator([]byte("benchmark_password"))
	if err != nil {
		b.Fatal(err)
	}
	conn := wrapPacketConn(discardPacketConn{}, ob)
	pkt := make([]byte, 1400) // a full-size QUIC packet

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := conn.WriteTo(pkt, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkWriteToSerial(b *testing.B) {
	ob, err := newSalamanderObfuscator([]byte("benchmark_password"))
	if err != nil {
		b.Fatal(err)
	}
	conn := wrapPacketConn(discardPacketConn{}, ob)
	pkt := make([]byte, 1400)

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := conn.WriteTo(pkt, nil); err != nil {
			b.Fatal(err)
		}
	}
}
