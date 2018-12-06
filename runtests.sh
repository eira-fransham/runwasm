#!/usr/bin/env sh

scriptdir="$(dirname "$0")"

cargo test --no-run --release --target wasm32-unknown-emscripten

filename="$(readlink -m "$(ls -t target/wasm32-unknown-emscripten/release/deps/*.wasm | head -n1)")"
jsname="$(echo "$filename" | sed 's/\.wasm$/\.js/')"

static_bump="$(rg -o 'STATIC_BUMP *= *(\d+)' -r '$1' "$jsname")"

old_folder="$(pwd)"
cd "$scriptdir" || exit
cargo run --release -- --static-bump "$static_bump" "$filename"
cd "$old_folder"
