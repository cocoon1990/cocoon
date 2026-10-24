#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  build-extension-wasm.sh
#
#  Wasm پروژه را می‌سازد و خروجی را در browser-extension/wasm/
#  قرار می‌دهد تا افزونه همان کد تست‌شدهٔ وب را اجرا کند
#  (نه یک بازنویسی JS که می‌تواند واگرا شود).
#
#  اجرا:  ./scripts/build-extension-wasm.sh
#  نیاز:  rustup target wasm32-unknown-unknown + wasm-pack
# ──────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/browser-extension/wasm"

echo "🔨 building browser-wasm..."
cd "$ROOT/browser-wasm"
wasm-pack build --release --target web --out-dir "$OUT"

echo "🧹 pruning typescript definitions (not needed at runtime)"
rm -f "$OUT"/*.d.ts "$OUT"/package.json "$OUT"/.gitignore

echo "✅ artifacts:"
ls -lh "$OUT"
