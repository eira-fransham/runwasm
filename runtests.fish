#!/usr/bin/env fish

set scriptdir (dirname (status --current-filename))

cargo test --no-run --release --target wasm32-unknown-emscripten

set filename (readlink -m (ls -t target/wasm32-unknown-emscripten/release/deps/*.wasm | head -n1))
set jsname (echo $filename | sed 's/\.wasm$/\.js/')

set static_bump (rg -o 'STATIC_BUMP *= *(\d+)' -r '$1' $jsname)

pushd $scriptdir
    cargo run --release -- --static-bump $static_bump $filename
popd
