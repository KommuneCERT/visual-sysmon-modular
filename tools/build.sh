#!/usr/bin/env bash
# Build everything that ends up in site/: data files (Python) and the WASM engine (Go).
# Uses a local Go toolchain when available, otherwise the golang Docker image.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM="$ROOT/vendor/sysmon-modular"
TOOLING="$UPSTREAM/tooling"
SITE="$ROOT/site"
GO_VERSION="${GO_VERSION:-1.22}"

[ -f "$TOOLING/go.mod" ] || { echo "submodule missing – run: git submodule update --init" >&2; exit 1; }

echo "▸ data files"
python3 "$ROOT/tools/build_catalog.py" --upstream "$UPSTREAM" --out "$SITE/data"

echo "▸ wasm wrapper"
mkdir -p "$TOOLING/cmd/vsmwasm" "$SITE/wasm" "$SITE/js/vendor"
cp "$ROOT/wasm/main.go" "$TOOLING/cmd/vsmwasm/main.go"

build_go() {
  cd "$TOOLING"
  GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$SITE/wasm/sysmon-modular.wasm" ./cmd/vsmwasm
  cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" "$SITE/js/vendor/wasm_exec.js"
}

if command -v go >/dev/null 2>&1; then
  build_go
else
  echo "  (no local go – using docker golang:$GO_VERSION)"
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
    -v "$ROOT:$ROOT" -w "$TOOLING" "golang:$GO_VERSION-alpine" sh -c "
      set -e
      GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o '$SITE/wasm/sysmon-modular.wasm' ./cmd/vsmwasm
      cp \"\$(go env GOROOT)/misc/wasm/wasm_exec.js\" '$SITE/js/vendor/wasm_exec.js'"
fi
rm -rf "$TOOLING/cmd/vsmwasm"
ls -la "$SITE/wasm/sysmon-modular.wasm" "$SITE/data/"
echo "✓ site/ ready – serve with: python3 -m http.server -d site 8080"
