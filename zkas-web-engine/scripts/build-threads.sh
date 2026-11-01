#!/bin/bash
# Multi-threaded wasm build of the web engine (atomics + shared memory), then bindings.
set -e
cd "$(git rev-parse --show-toplevel)" && export PATH=/root/.cargo/bin:$PATH

export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target/wasm-threads}
export RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=4294967296 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base -C link-arg=--export=__heap_base -C link-arg=--export=__data_end'
nice -n 5 cargo +nightly-2026-06-20 build --release -p zkas-web-engine --features threads --target wasm32-unknown-unknown -Z build-std=panic_abort,std 2>&1 | grep -E "^(error|warning: unused)" -A8 | head -40
W=$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/zkas_web_engine.wasm; ls -la $W
O=${OUT:-target/webengine-pkg-threads}; rm -rf $O; wasm-bindgen --target web --out-dir $O $W
ls $O; ls $O/snippets 2>/dev/null | head

# wasm-bindgen-rayon's helper imports the package as '../../..' (a bundler-only directory import).
H=$(ls -d ${OUT:-target/webengine-pkg-threads}/snippets/wasm-bindgen-rayon-*/src/workerHelpers.js)
sed -i "s#import('../../..')#import('../../../zkas_web_engine.js')#; s#from '../../..'#from '../../../zkas_web_engine.js'#" $H
grep -n "zkas_web_engine.js\|\.\./\.\./\.\." $H | head
