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
	"bytes"
	"net"
	"testing"
	"time"
)

// TestSalamanderV2OverRealSockets exercises the whole wrapper over two UDP
// sockets. The unit tests drive the obfuscator directly, which cannot catch a
// mistake in how it is wrapped -- a role mixed up between the two ends, or a
// buffer sized wrong once pooling is involved.
func TestSalamanderV2OverRealSockets(t *testing.T) {
	serverSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverSock.Close()
	clientSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientSock.Close()

	const password = "a_reasonable_password"
	server, err := WrapPacketConnSalamanderV2(serverSock, []byte(password), "", RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	client, err := WrapPacketConnSalamanderV2(clientSock, []byte(password), "", RoleClient)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("a datagram that must survive the round trip intact")
	if _, err := client.WriteTo(payload, serverSock.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, from, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server did not receive the datagram: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload changed in transit: got %q", buf[:n])
	}

	// And back the other way, which is what exercises the second key.
	reply := []byte("and the reply")
	if _, err := server.WriteTo(reply, from); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client did not receive the reply: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("reply changed in transit: got %q", buf[:n])
	}
}

// A server speaking v2 must ignore a v1 client entirely rather than half-decode
// it. There is no compatibility mode: v1 and v2 are separate deployments.
func TestSalamanderV2IgnoresV1(t *testing.T) {
	serverSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverSock.Close()
	clientSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientSock.Close()

	const password = "a_reasonable_password"
	server, err := WrapPacketConnSalamanderV2(serverSock, []byte(password), "", RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	v1Client, err := WrapPacketConnSalamander(clientSock, []byte(password))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v1Client.WriteTo([]byte("v1 speaking"), serverSock.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, _, err := server.ReadFrom(buf); err == nil {
		t.Error("a v2 server accepted a v1 packet")
	}
}
