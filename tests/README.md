# Test bed

A network impairment test bed for the transport: run a real server and a real
client against each other over a link that loses, delays and throttles packets
on purpose, and measure what gets through.

It exists so that acceptance criteria can be written as numbers. Before this,
the only performance test in the tree was `core/server/copy_benchmark_test.go`,
which times a `bytes.Reader` into `io.Discard` — no syscalls, no UDP, no
reassembly, no congestion control. "Throughput must not regress by more than
X%" was not a checkable claim.

## Layout

| Path | What it is |
| --- | --- |
| `netem/` | The user-space impairment layer. Wraps a `net.PacketConn`; no root, works everywhere. **This is the main deliverable.** |
| `netem/kernel/` | Optional driver for the real kernel shaper (`tc`/netem on Linux, dummynet on macOS). Needs root, opt-in, skipped by default. |
| `metrics/` | Percentiles, throughput, regression arithmetic. |
| `harness/` | Brings up a core server + client over an impaired link, and measures throughput, latency and failover. `multipath.go` gives one server several candidate addresses. |
| `e2e/` | End-to-end tests and benchmarks built on the harness. |

## Running

```sh
cd tests

go test ./... -count=1              # everything; a few minutes
go test ./... -count=1 -short       # skips the tests that wait out QUIC timeouts
go test ./netem/... ./metrics/ -race -count=1   # the layer's own tests, fast

go test ./e2e/ -run '^$' -bench . -benchtime 5x  # the regression baseline
```

`-benchtime` is given in iterations, not seconds: one iteration moves a fixed
4MB, and an impaired profile makes that slow on purpose.

Nothing here needs root, a container, or a network. Everything binds
`127.0.0.1`.

## Profiles

`netem.Standard()` is the impairment matrix the transport is expected to
survive. Naming a profile is how a criterion says what conditions it means.

| Profile | Link | What it is for |
| --- | --- | --- |
| `clean` | pass-through | The baseline. Every comparison is against this, never against a bare socket. |
| `loss1%` | 1% each way | Ordinary bad wifi / congested uplink. |
| `loss5%` | 5% each way | A link the user would call broken. Loss recovery and the tail latency it costs. |
| `rtt50ms` | 25ms each way | Same-continent path. |
| `rtt200ms` | 100ms each way | Intercontinental path, or one relayed through one. Bandwidth-delay product starts to bind. |
| `rtt200ms+loss1%` | both | The realistic censored-network case: far away *and* lossy. |
| `rtt50ms+loss5%` | both | Aggressive interference on a near path. |
| `rate1MB/s+rtt50ms` | token bucket + delay | Throttling rather than blocking — the soft-censorship case. |

Two more are used directly rather than through the matrix:

- `netem.Blocked()` — UDP fully blackholed. Writes still succeed, nothing ever
  comes back. This is what a censor that has decided to kill QUIC looks like
  from the endpoint. The client cannot connect at all; the test asserts that it
  fails rather than hangs.
- `netem.RateLimited(n)` — a token bucket on its own.

Profiles compose: `netem.RTT(200*time.Millisecond).WithLoss(0.01).WithJitter(20*time.Millisecond)`.

Loss and delay are configured **per direction**. An RTT of 200ms is 100ms of
one-way delay on each side, and 5% loss means each datagram is dropped with
probability 0.05 on each crossing.

## What the user-space layer models, and what it does not

`netem.Conn` wraps a `net.PacketConn` and applies, per datagram: an independent
loss draw, a delay with optional jitter, and a token bucket with a finite queue.
Only one endpoint needs wrapping — every packet of an exchange crosses the
client's socket exactly once in each direction — and the harness wraps the
client.

Faithful enough to assert on:

- Loss rates come out within a fraction of a point of the configured value; the
  counters (`Controller.Stats()`) report exactly what was dropped, so a test can
  check the impairment actually happened rather than assuming it.
- Delay is accurate to about a millisecond. Measured p50 for `rtt50ms` is 50.7ms
  and for `rtt200ms` is 200.8ms.
- The shaper's output cannot exceed its configured rate.

Known divergences from a real network — read these before trusting an absolute
number:

- **No GSO, no ECN, no batched syscalls.** A `netem.Conn` is not a
  `*net.UDPConn`, so quic-go falls back to its portable single-packet path. This
  costs throughput even with the `clean` profile. **Always take the baseline
  through `clean`**, never against an unwrapped socket, or the wrapper's own
  overhead will be attributed to whatever change is being measured.
- **Loss is independent per packet.** Real networks lose in bursts, which is
  harder on recovery than the same average rate spread evenly.
- **Delay is applied at the socket boundary**, so it does not interact with the
  kernel's own queueing, pacing or offloads.
- **Every delayed packet goes through a scheduler goroutine and a heap.** At
  very high packet rates that is a CPU cost the real network does not have.
- Datagrams delivered but not read fast enough are dropped and counted as
  `Stats.Overflow`, separately from link loss. A result that depends on
  `Overflow` is measuring the harness, not the transport.
- **TCP cross traffic is impossible and will stay impossible.** The layer wraps
  a `net.PacketConn`; TCP does not go through one. A competing flow has to be a
  second QUIC client (see below), not `iperf`.

## Shared bottlenecks

`Link.Rate` gives every `Conn` its own token bucket and its own queue, so two
flows cannot take capacity from each other — which makes it useless for asking
what an aggressive sender costs its neighbours, since the answer is fixed at
"nothing" before the experiment starts.

`netem.NewBottleneck(bytesPerSec, bufferDelay)` is one bucket and one buffer for
every `Link` pointing at it. Reservations are served in call order, so the flows
share the capacity in proportion to how hard each pushes, and a flow that keeps
the buffer full makes its neighbour's datagrams tail-drop.

```go
up, down := netem.NewBottleneck(1<<20, 100*time.Millisecond), netem.NewBottleneck(1<<20, 100*time.Millisecond)
p := netem.RTT(50 * time.Millisecond).WithSharedBottleneck(up, down)

env := harness.New(t, harness.Options{Profile: p, Bandwidth: harness.Bandwidth{BytesPerSec: 2 << 20}})
peer, _ := env.AddClient(p, seed, harness.Options{}) // no declaration -> BBR
```

Each flow needs its own `Controller`, because `Controller.Stats` sums every
`Conn` it made and a shared one could not say which flow moved which bytes;
`AddClient` makes one. Pass a separate `Bottleneck` per direction unless the
point is a half-duplex medium.

Always run the two-identical-controllers cell as a control. Whatever share two
BBR flows get is the share the bed itself hands out, and a Brutal number only
means something as a departure from it.

## Candidates: several paths to one server

A criterion about failover is a statement about several paths at once — "the
candidate in use died, the connection moved to one that did not". Two things
make that expressible.

**`Ctrl.SetFor(peer, profile)` impairs one candidate.** Without it the profile
covers the whole socket, so "candidate A is dead and candidate B is fine" cannot
be said at all.

```go
env := harness.New(t, harness.Options{Candidates: 3})
for _, leg := range env.Paths.Legs {
	env.Ctrl.SetFor(leg.Key(), netem.RTT(50*time.Millisecond))
}
env.Ctrl.SetFor(env.Paths.Legs[0].Key(), netem.Blocked())   // kill the one in use
env.Ctrl.ClearFor(env.Paths.Legs[0].Key())                  // back to the default profile
stats := env.Ctrl.StatsFor(env.Paths.Legs[2].Key())         // did the traffic actually move?
```

A candidate is identified here by its **peer address** — the destination of a
datagram going up, the source of one coming down. The alternatives do not work:
one client socket reaches every candidate at once and is thrown away on every
reconnect, so the local socket cannot name a candidate, and a synthetic index
has nowhere to live in `net.PacketConn`. The peer address is the only thing
present symmetrically at both ends of the interface this layer implements, and
it is also what a Selector chooses between, so a test and the code under test
name the same object. The consequence: two candidates that differ only in
something invisible here — the same server address reached over two local
interfaces — are one candidate.

`SetFor` also gives a candidate counters of its own, read back with `StatsFor`.
That is the other half of an assertion: the profile says which leg was supposed
to die, the counters say which leg the traffic actually took. Naming a candidate
with the *default* profile is therefore a meaningful call — it buys separate
counters for a leg the test does not want to impair. A candidate no `SetFor` ever
named reports zero from `StatsFor`; its traffic is in `Stats()` along with
everyone else's.

Each candidate gets its own pipes, so a datagram held up on a slow leg does not
delay one on a fast leg, and each leg's loss draws come from a stream derived
from the seed and the address — reproducible, and unchanged by adding another
candidate. `ClearFor` reverts the impairment but not the split, so counters
carry on across it.

**`harness.MultiPath` gives one server several addresses.** `Options.Candidates`
puts N forwarding legs on `127.0.0.1` in front of the server socket. The server
sees a distinct source address per leg — the shape a candidate set has on the
wire — while there is still one server, one certificate, one authenticator. It
is a forwarder rather than several listeners because `core/server` takes exactly
one `Conn`; several is a P2 change.

```go
env := harness.New(t, harness.Options{Candidates: 3})  // client dials Legs[0]
env.Paths.Legs[1].Addr()                               // what a candidate looks like
env.Paths.Legs[1].Stats().FromServer                   // where the server is answering
env.Paths.Legs[0].RewriteSourceTo(env.Paths.Legs[1])   // on-path source rewriting
```

`RewriteSourceTo` is the reason this is a forwarder we own rather than a real
multi-homed setup: it puts a leg's datagrams on another leg's socket, so the
server sees a different source for packets that are otherwise entirely genuine —
not forged, not replayed, not modified. That is an on-path attacker, and the
server's reaction to one is a security property. `TestUnfilteredPathFollowIsHijackable`
holds the current answer: the server follows, unconditionally, and neither
endpoint notices. It is not asserting that this is correct — it is the recorded
evidence that the design's `PathChangeFilter` has a reason to exist.

**Do not build any of this on `extras/transport/udphop`.** Its `PacketConn` lies
to the layer above in both directions: `ReadFrom` returns the constant `u.Addr`
instead of the datagram's real source, and `WriteTo` ignores its `addr` argument
entirely — see the *"Skip the check for now, always write to the server"* comment
in `conn.go`. A bed whose whole job is telling candidates apart by address
cannot stand on a conn that erases the address. Port hopping is a candidate
*generation* strategy; it is not a multi-path abstraction.

Two limits worth knowing before writing a test against this:

- **There is no Selector yet.** `core/client` dials a single `ServerAddr`, so the
  extra legs are reachable but unused, and killing the one in use kills the
  client — `TestBlackholingTheCandidateInUseStrandsTheClient` records exactly
  that, and `TestFailoverToLivingCandidate` is the same scenario written out and
  skipped, waiting for `extras/realm/selector.go`.
- **A `MultiPath` assumes one client.** The legs share the client address they
  relay back to, which is what lets a leg used only as a forged source still
  reach the client. A second client through the same `MultiPath` would take the
  first one's return traffic.

## Kernel mode

For results that must survive contact with the real datapath, `netem/kernel`
drives the platform shaper instead. It is **off unless three things hold**:

1. `HYSTERIA_NETEM_KERNEL` is set — it changes global network state, so it is
   never implicit.
2. The process is root.
3. The tools exist: `tc` on Linux, `dnctl` and `pfctl` on macOS.

Otherwise `kernel.Check()` returns a reason and the test skips with it printed.

```sh
sudo HYSTERIA_NETEM_KERNEL=1 go test ./e2e/ -run TestKernelNetem -v
```

What it does:

- **Linux**: `tc qdisc replace dev lo root netem …`, removed with
  `tc qdisc del dev lo root` on teardown. Scoped to the loopback interface.
- **macOS**: a dummynet pipe plus pf rules in a dedicated `hysteria-netem`
  anchor, removed on teardown along with the `pfctl -E` token. pf rules are
  global, so **for the duration of the test all UDP on the machine is shaped**,
  not just loopback.

Kernel profiles must be symmetric: the shaper sits on one interface and treats
both directions alike.

The macOS path has not been exercised — this machine cannot run it without root
— so treat it as a starting point rather than a verified recipe.

## Skips you should expect

| Where | Why |
| --- | --- |
| `TestKernelNetemMatchesUserspace` | Always skipped unless kernel mode is enabled, as above. |
| `TestFullyBlockedUDPPreventsConnection`, `TestFailoverAfterUDPBlackhole`, `TestBlackholingTheCandidateInUseStrandsTheClient` | Skipped under `-short`: they spend real seconds waiting out QUIC's handshake and idle timeouts, which is the thing being measured. |
| `TestFailoverToLivingCandidate` | Always skipped: there is no Selector, so nothing can move a connection between candidates. It is written out in full as the landing point for P1b. |
| Everything in `e2e/pathfail_test.go` | Skipped under `-short`: each case holds a live connection for eleven or twelve seconds, because the detection latencies being measured are seconds long. |

## Indicative numbers

Measured on an Apple M4, macOS, 4MB transfers, user-space layer. They are here
to show the shape of the results and to catch an order-of-magnitude mistake —
not as thresholds. Take a fresh baseline on the machine doing the comparing.

| Profile | Throughput | Round trip p50 |
| --- | --- | --- |
| clean | ~95 MB/s | 0.19ms |
| loss1% | ~100 MB/s | 1.5ms |
| loss5% | ~59 MB/s | — |
| rtt50ms | ~15 MB/s | 50.7ms |
| rtt200ms | ~4 MB/s | 200.8ms |
| rate1MB/s+rtt50ms | ~0.95 MB/s | — |

Failover, measured with a 4s QUIC idle timeout and the link blackholed for 6s:
the client declared the connection dead 5.0s after the cut, and the first
exchange succeeded 1.0s after the link came back.

## Adding a measurement

Everything a test asserts on comes from `harness.Env`, so a new criterion should
be a method there rather than a bespoke setup in a test:

```go
env := harness.New(t, harness.Options{Profile: netem.RTT(200 * time.Millisecond)})
bps, err := env.TCPThroughput(4<<20, 60*time.Second)
samples, err := env.TCPLatency(100, 3, 2*time.Millisecond, 8*time.Second)
f, err := env.MeasureFailover(6*time.Second, 2*time.Second, 30*time.Second)

// Timestamped round trips, for a claim about how a number moves over a
// transfer rather than what it averaged. Stop it when the load stops:
// samples taken afterwards describe an idle link.
series, err := env.LatencySeries(harness.Probe{
	Count: 500, Gap: 100 * time.Millisecond, Payload: 100, Stop: done,
})
// Time-bounded rather than size-bounded, so two flows are comparable by the
// bytes each moved over the same interval.
n, err := env.TCPLoadFor(env.Client, 12*time.Second)
```

## Watching a connection break

`MeasureFailover` answers "how long was the outage". `Env.Observe` answers the
different question a Selector has to answer: *what did this look like from
inside the endpoint, and could it have been told from a path that was merely
bad*. It runs load, changes the link underneath it at a chosen moment, and
records two streams at once — `client.PathStatsProvider` readings at a chosen
interval, and the outcome of every application exchange.

```go
env := harness.New(t, harness.Options{Profile: netem.RTT(50 * time.Millisecond)})
rep := env.Observe(harness.Observation{
	Gap: 50 * time.Millisecond, Payload: 100,        // or Bulk: true
	Sample: 20 * time.Millisecond, ExchangeTimeout: 2 * time.Second,
	FaultAt: 2 * time.Second, Duration: 11 * time.Second,
	Fault: netem.RTT(50 * time.Millisecond).WithUpBlackhole(true),
})
sig := rep.Signature()             // only what a caller of the core could read
fired := rep.DetectAt(2 * time.Second) // when a silence detector would have fired
upIn, upOut, _, _ := rep.Delivered()   // netem's ground truth, for confirming the fault
```

The split is the point and it is enforced by keeping the two on separate types.
A `Signature` contains nothing that is not reachable through the core's public
surface, so any detector keyed on one of its fields is a detector that can be
built. `Delivered` and the `netem.Stats` snapshots beside it are ground truth
that only the bed has: they belong in the `require` that proves the scenario
ran, and nowhere else.

`Profile.WithUpBlackhole` and `WithDownBlackhole` kill one direction. They are
not symmetric in what they leave observable, which is a finding rather than an
inconvenience — see `e2e/pathfail_test.go`, whose closing comment carries the
numbers and the recommendation the Selector's detector should be built on.

## Baselines

The `Baseline` tests are not assertions. They print tables, and the tables are
what a change gets compared against:

```sh
go test ./e2e/ -run Baseline -v -timeout 30m           # end to end
go test -C ../core ./internal/congestion/brutal/ -run Baseline -v
```

The second one exists because `ackRate` and the congestion window are internal
to the core and this module cannot import them, so the numbers that decide
Brutal's behaviour have to be taken by driving the controller directly.

`env.Ctrl` changes the link while traffic is running — that is how failover is
measured, and it applies to sockets the client creates later, so a reconnect
lands on the same conditions. `SetFor` and `StatsFor` behave the same way, and
their per-candidate counters survive a socket close: the numbers that prove
where the traffic went have to outlive the reconnect they are about.
