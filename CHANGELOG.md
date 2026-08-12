# Changelog

chameleon has not had a release yet. Changes since forking from
[Hysteria 2](https://github.com/apernet/hysteria) are listed here; once there is a
first tag, this file switches to per-release sections.

## Unreleased

### Removed

- The update check against `api.hy2.io`, and with it the whole phone-home path. It
  only logged that a newer version existed; it never updated anything. A fixed
  endpoint every client contacts is a beacon that identifies users and can be
  blocked or enumerated. The `--disable-update-check` flag and
  `HYSTERIA_DISABLE_UPDATE_CHECK` are gone with it.
- Upstream's release infrastructure: the publish-to-API step in `hyperbole.py` and
  the Cloudflare R2 upload in the release workflow, both of which used credentials
  and buckets belonging to apernet.

### Changed

- **Wire compatibility with Hysteria and sing-box is intentionally broken.** See the
  table in [README.md](README.md) and the spec in [PROTOCOL.md](PROTOCOL.md).
  - Authentication headers `Hysteria-*` → `Cham-*`.
  - Authentication success is a plain `200` instead of `233`. Because the
    masquerade handler can also answer `200`, clients must additionally require the
    `Cham-UDP` header; `233` was a giveaway to any censor holding working
    credentials. `masquerade.string.statusCode` no longer excludes `233`, since no
    status code is reserved any more.
  - URI scheme `hysteria2://` / `hy2://` → `chameleon://` / `chm://`.
  - Hole-punch magic `HYRLMv1` → `CHRLMv1`.
- Go module path → `github.com/chameleon-protocol/chameleon/{core,extras,app}/v2`.
- Config search path `/etc/hysteria`, `$HOME/.hysteria` → `/etc/chameleon`,
  `$HOME/.chameleon`. Environment variables `HYSTERIA_*` → `CHAMELEON_*`. Build
  variables `HY_APP_*` → `CHM_APP_*`.
- Host-visible names: nftables table `hysteria_<hash>` → `chameleon_<hash>`, chain
  `HYSTERIA-PR-` → `CHAMELEON-PR-`, UPnP port-mapping description `hysteria-realm`
  → `chameleon-realm` (this one shows up in router admin pages).
- The install script discovers versions through the GitHub Releases API instead of a
  project-owned endpoint. Container images publish to `ghcr.io` instead of a
  DockerHub account we do not own.

### Added

- [`docs/research/architecture.md`](docs/research/architecture.md): the architecture
  study behind the direction — current-state map, the reviewed design alternatives
  and why two of three were rejected, the staged roadmap, and a ROI-ordered list of
  improvements.
