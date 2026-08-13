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

// Package realm implements Hysteria Realms: rendezvous-assisted UDP hole
// punching between a client and a server that are both behind NAT.
//
// # Lifecycle
//
// Punching is not a phase that ends when the connection starts. PunchPacketConn
// is meant to sit under QUIC for the whole life of the socket: it splits every
// inbound packet into STUN responses, punch packets for registered attempts,
// and everything else, which goes up to the reader. Puncher registers an
// attempt, sends on the same socket, and takes its packets from that demux, so
// an attempt can start at any moment — before the connection exists, and again
// afterwards when the network changes underneath a live connection. Several
// attempts can run at once; each has its own ID and its own event channel.
//
// Before QUIC owns the socket nobody is reading it, and a demux with no reader
// sees nothing. PunchPacketConn.StartPump fills that gap and StopPump hands the
// socket back, queueing what arrived in between so the handover loses nothing.
//
// The package-level Punch on a plain PacketConn still reads the socket
// exclusively. That path exists for bootstrapping a socket QUIC has not been
// given yet; it cannot be used again once the connection is up.
//
// Punch packets carry a clear-text four-byte attempt tag derived from the
// metadata, which is what lets the demux find the attempt with a map lookup.
// The alternative — trial-decrypting each packet against every in-flight
// attempt — is a cost multiplier an attacker controls by spraying packets, and
// permanent punching means paying it forever. The tag makes packets of one
// attempt linkable to each other, which the address pair already did.
//
// # Trust model
//
// The rendezvous server is a meeting point, not an authority. It sees every
// address a peer announces and every byte of the punch metadata it relays, so
// it must be treated as an active attacker that can add, drop, delay or forge
// anything it forwards.
//
// What the rendezvous server can do:
//
//   - Deny service: refuse to relay, delay, or hand out addresses that never
//     answer. Availability is not defended here.
//   - Learn the reflexive addresses of every peer in a realm, and correlate
//     which peers talk to each other and when.
//   - Read and replay the punch metadata (nonce and obfuscation key). Punch
//     packets are obfuscated, not authenticated, so the rendezvous server can
//     mint packets that any peer in the attempt will decode as valid.
//   - Announce addresses that do not belong to the peer, i.e. steer a client
//     at a machine of its choosing, as long as it announces that machine.
//
// What the rendezvous server cannot do:
//
//   - Hand a peer a QUIC address it never announced. Punch only reports a
//     source address that appears in the candidate set derived from the
//     addresses the attempt started with (see PunchSourcePolicy), so packets
//     injected from an unrelated address are dropped instead of becoming the
//     QUIC peer. Candidates are also filtered and capped, which bounds how
//     much punch traffic a malicious realm can aim at a third party.
//   - Impersonate the Hysteria server to a client that pins it. The QUIC
//     handshake that follows the punch verifies the server certificate, which
//     the rendezvous server has no way to influence.
//
// The last point holds only under its precondition, and callers should read it
// as a requirement rather than a guarantee: with a pinned certificate (or an
// SNI the rendezvous server cannot obtain a certificate for) a steered client
// fails the handshake, but a client that verifies against the rendezvous
// hostname with WebPKI defaults will happily complete a handshake with the
// rendezvous server itself — and since the Hysteria password travels from
// client to server inside that TLS session, that is a credential disclosure,
// not only a redirect.
//
// The boundary, stated positively: the rendezvous server picks which announced
// address a peer talks to and can observe that it happened, but authentication
// of that peer comes entirely from the certificate and the password carried in
// the QUIC handshake. Nothing in this package authenticates a peer, and callers
// must not treat a completed punch as proof of identity.
//
// # Announcing local addresses
//
// Peers announce their own interface addresses (LocalCandidates) alongside the
// reflexive ones, because two peers on the same LAN otherwise have to reach
// each other by NAT hairpin, which many gateways do not implement. This widens
// what the rendezvous server learns: it now sees the announcer's internal
// topology, not just its public address. That is a disclosure to an entity
// already trusted with the peer's reflexive address and its communication
// graph, and it buys the case the rendezvous server cannot help with at all —
// a direct LAN path that never leaves the link.
//
// It also has a security-relevant upside. The initiator only accepts punch
// packets from sources in its candidate set, so an incomplete candidate set is
// not merely a missed path: a peer that punches from an address it never
// announced has its packets dropped. Enumerating local addresses is what keeps
// that filter from rejecting the legitimate same-LAN peer.
//
// # Initiator and responder differ on purpose
//
// The initiator (Punch, run by the client) accepts punch packets only from its
// candidate set, including the ports predicted for symmetric NAT peers. This
// costs the client almost nothing: a client behind an address-restricted or
// symmetric NAT can only receive from addresses it has already sent to, so the
// filter mostly re-states what its own NAT enforces, while removing the case
// where a peer with an open path (full-cone NAT, or no NAT at all) hands its
// QUIC socket to whoever spoke first.
//
// The responder (ServerPuncher.Respond, run by the server) defaults to
// accepting any source, because that is the case the filter cannot cover: a
// client behind a symmetric NAT is seen from a port nobody could predict, and
// sometimes from a different IP when the carrier NAT pools addresses. A
// responder that is usually reachable is also the side that loses least by
// being permissive, since it authenticates the peer in the QUIC handshake that
// follows. Callers that know their peers are well behaved can tighten this
// with PunchConfig.SourcePolicy.
//
// # Endpoint-dependent (symmetric) NAT
//
// A NAT that allocates a fresh external port per destination hides the port a
// peer would have to punch at. ClassifyNAT calls that out from the addresses a
// peer announced: two ports on one host is conclusive, anything else is not.
//
// When the peer is endpoint-dependent and we are not, the punch guesses ports,
// paced at 100 per second for at most 20 seconds (1024 guesses, about 10
// seconds and 550 KB of hello packets). The guesses are ordered by yield:
// neighbours of the announced ports first, since a NAT that allocates
// sequentially is both common and cheap to hit; then the announced stride
// extrapolated; then uniform random ports.
//
// What the random tier is worth, honestly. With N = 64512 guessable ports, n
// guesses and m concurrent mappings on the peer's side, the chance of a hit is
// 1 - (1 - n/N)^m ≈ 1 - e^(-nm/N). The peer's mappings are per destination
// endpoint, so m is the number of our addresses it punches at — typically one
// or two. n = 1024 against m = 1 is 1.6%, not the 98% the birthday paradox
// promises. That number needs m in the hundreds, i.e. the peer sending from
// hundreds of sockets at once so its NAT hands out hundreds of ports for us to
// guess among (n = m = 512 gives 98%, n = m = 1024 gives ~100%). Nothing here
// does that: the socket that wins would be the one the connection has to run
// on, so it belongs with connection setup rather than with an attempt on an
// existing socket. Until that exists, the sequential tiers carry this feature
// and the random tier is a small bonus.
//
// When both ends are endpoint-dependent, neither can predict the other and the
// probability collapses to nm/N² — a search that takes tens of minutes at any
// sane packet rate. That case gives up after BothEndsTimeout (2s by default,
// enough for a LAN or hairpin path that needs no prediction) and returns
// ErrSymmetricNATBothEnds, which callers should treat as "use a relay", not as
// a transient failure.
//
// Probing widens what a malicious rendezvous server can aim at a third party:
// up to 1024 packets per attempt instead of a handful. The rate limit, the
// probe budget, and maxSymmetricNATProbes bound it, and only hosts that
// announced several ports are probed at all.
//
// # Known gap: metadata confidentiality
//
// PunchMetadata is generated by the initiator and relayed verbatim by the
// rendezvous server, so the obfuscation key is not a secret between the two
// peers. Removing that requires peer identity the rendezvous server does not
// hold — for example a per-peer static public key, with the metadata sealed to
// it — which is the same key material the planned mesh identity layer needs.
// Until then, punch packets defend against passive on-path classifiers, not
// against the rendezvous server.
package realm
