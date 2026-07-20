#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${VERSION:-dev}
COMMIT=${COMMIT:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || printf unknown)}
GOOS=${GOOS:-linux}
GOARCH=${GOARCH:-amd64}
OUT=${OUT:-"$ROOT/artifacts/c2hunter-sensor-${VERSION}-${GOOS}-${GOARCH}.tar.gz"}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$(dirname "$OUT")" "$STAGE/c2hunter-sensor"
(
  cd "$ROOT/sensor"
  CGO_ENABLED=1 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -tags netgo,osusergo \
    -ldflags "-s -w -linkmode external -extldflags -static -X main.version=$VERSION -X main.commit=$COMMIT" \
    -o "$STAGE/c2hunter-sensor/c2hunter-sensor" ./cmd/c2hunter-sensor
)
cp "$ROOT/scripts/install-sensor.sh" "$STAGE/c2hunter-sensor/install-sensor.sh"
cp "$ROOT/deploy/sensor/config.yaml" "$ROOT/deploy/sensor/environment" "$ROOT/deploy/sensor/c2hunter-sensor.service" "$STAGE/c2hunter-sensor/"
chmod 0755 "$STAGE/c2hunter-sensor/c2hunter-sensor" "$STAGE/c2hunter-sensor/install-sensor.sh"
tar -C "$STAGE" -czf "$OUT" c2hunter-sensor
printf '%s\n' "$OUT"
