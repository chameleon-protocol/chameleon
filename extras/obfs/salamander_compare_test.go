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

// BenchmarkSalamanderV1vsV2 measures what v2 costs on the send path, through
// the same wrapper the real code uses but over a discard socket, so the number
// is the obfuscation itself and not the kernel.
//
// Read this alongside the fact that enabling any obfuscation already drops the
// connection to one sendto per packet: obfsPacketConn does not implement
// ReadMsgUDP/WriteMsgUDP, so quic-go treats it as a basic conn and neither GSO
// nor ECN applies. A syscall is 1-2 microseconds, which is the scale the
// difference below should be judged against.
func BenchmarkSalamanderV1vsV2(b *testing.B) {
	pkt := make([]byte, 1400)

	b.Run("v1", func(b *testing.B) {
		ob, err := newSalamanderObfuscator([]byte("benchmark_password"))
		if err != nil {
			b.Fatal(err)
		}
		conn := wrapPacketConn(discardPacketConn{}, ob)
		benchWrite(b, conn, pkt)
	})

	b.Run("v2", func(b *testing.B) {
		ob, err := NewSalamanderV2([]byte("benchmark_password"), "", RoleClient)
		if err != nil {
			b.Fatal(err)
		}
		conn := wrapPacketConn(discardPacketConn{}, ob)
		benchWrite(b, conn, pkt)
	})
}

func benchWrite(b *testing.B, conn net.PacketConn, pkt []byte) {
	b.Helper()
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
