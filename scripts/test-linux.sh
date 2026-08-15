#!/usr/bin/env bash
# Run the test suite on Linux in a container.
#
# Several tests cannot pass on a macOS host and are not broken: anything binding
# an address in 127.0.0.0/8 other than 127.0.0.1 (macOS has only the one),
# anything behind a linux build tag (sockopts, firewall, tproxy), and the kernel
# impairment mode, which needs tc and root. Running them here is the difference
# between "known to fail on this host" and "known to pass somewhere".
#
# Test runs have no network at all: the image carries the Python the
# client-driving tests need, and the host module cache is mounted read only, so
# a test can never fail because a package index was unreachable. --kernel gives
# the container NET_ADMIN and a network namespace of its own so tests/netem/kernel
# can install tc rules; those rules live and die with the container and are not
# visible to the host's interfaces. Nothing here touches the host's networking.
#
#   scripts/test-linux.sh                     # everything
#   scripts/test-linux.sh ./internal/frag/... # one package pattern
#   scripts/test-linux.sh --kernel ./netem/...
set -euo pipefail

IMAGE=chameleon-test
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MODCACHE=${GOMODCACHE:-$(go env GOMODCACHE)}

kernel=0
args=()
for a in "$@"; do
  case "$a" in
    --kernel) kernel=1 ;;
    *) args+=("$a") ;;
  esac
done
[ ${#args[@]} -eq 0 ] && args=(./...)

# Building is the one step that needs the network, and it is skipped once the
# image exists. Rebuild by hand after editing the Dockerfile.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE (one time, needs network)..." >&2
  docker build -q -t "$IMAGE" -f "$ROOT/scripts/test-linux.Dockerfile" "$ROOT/scripts" >/dev/null
fi

run=(docker run --rm --network none)
if [ "$kernel" = 1 ]; then
  # A namespace of its own, not the host's. tc inside it is invisible outside.
  run=(docker run --rm --network bridge --cap-add NET_ADMIN)
fi

exec "${run[@]}" \
  -v "$ROOT":/src -v "$MODCACHE":/gomod:ro \
  -e GOMODCACHE=/gomod -e GOPROXY=off \
  -w /src "$IMAGE" sh -c '
    fail=0
    for m in core extras app tests; do
      # A package pattern names packages in one module; skip the modules where
      # it matches nothing rather than reporting that as a failure.
      (cd "$m" && go list '"${args[*]}"' >/dev/null 2>&1) || continue
      echo "=== $m ==="
      (cd "$m" && go test -count=1 '"${args[*]}"' 2>&1 | grep -E "^(ok|FAIL|--- )") || fail=1
    done
    exit $fail
  '
