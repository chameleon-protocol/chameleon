# chameleon

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE.md)

**A censorship-resistant transport that keeps working when the network does not.**

chameleon is a QUIC-based transport built for networks that actively interfere with
you: DPI that classifies and blocks, QoS that throttles UDP into uselessness, NATs
that refuse to hold a mapping, and paths that disappear mid-session. The goal is not
to be the fastest proxy on a cooperative network — it is to still be connected on a
hostile one.

It is a fork of [Hysteria 2](https://github.com/apernet/hysteria) and inherits its
QUIC data plane, Brutal congestion control, and HTTP/3 masquerade.

## Status

**Early. Not ready for production, and not yet a mesh.**

What works today is what Hysteria 2 already did: a fast QUIC proxy with SOCKS5 /
HTTP / TUN / TProxy / redirect / port-forwarding inbounds, Salamander and Gecko
obfuscation, and UDP hole punching via the `realm` rendezvous.

What we are building toward is a Tailscale-shaped overlay: peers that find each
other, survive endpoint changes without dropping the session, and fall back through
progressively less pleasant paths — direct UDP, port hopping, TCP, relay — rather
than failing outright. See [`docs/research/architecture.md`](docs/research/architecture.md)
for the architecture study, the reviewed design alternatives, and the staged roadmap.

## Not compatible with Hysteria

chameleon deliberately breaks wire compatibility with upstream Hysteria and with
third-party implementations such as sing-box. The identifiers that made them
interoperable — the `Hysteria-*` authentication headers, the non-standard `233`
status code, the `hysteria2://` URI scheme — are also exactly what a censor greps
for after buying a subscription. They are gone.

| | Hysteria 2 | chameleon |
|---|---|---|
| Auth headers | `Hysteria-Auth`, `Hysteria-UDP`, `Hysteria-CC-RX`, `Hysteria-Padding` | `Cham-Auth`, `Cham-UDP`, `Cham-CC-RX`, `Cham-Padding` |
| Auth success | `233 HyOK` | plain `200` with `Cham-UDP` present |
| Auth `:host:` | `hysteria` | `chameleon` |
| URI scheme | `hysteria2://`, `hy2://` | `chameleon://`, `chm://` |
| Config dir | `/etc/hysteria`, `$HOME/.hysteria` | `/etc/chameleon`, `$HOME/.chameleon` |
| Env prefix | `HYSTERIA_*` | `CHAMELEON_*` |

Renaming these constants only moves the target — they are still fixed strings.
Deriving them from the pre-shared key is the real fix, and is on the roadmap.

chameleon also does not phone home. Upstream's update check against `api.hy2.io`
has been removed: a fixed endpoint that every client contacts is a beacon that
identifies users and can be blocked or enumerated.

See [PROTOCOL.md](PROTOCOL.md) for the wire specification.

## Building

```bash
python hyperbole.py build
```

Requires Go (version pinned in `go.work`) and Python 3. The binary lands in `build/`.

## License

MIT — see [LICENSE.md](LICENSE.md). Copyright in the upstream work this derives from
remains with the Hysteria authors.
