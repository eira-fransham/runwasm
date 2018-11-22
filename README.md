![](./runwasm.png)

Ever wanted to run your systems language code with significantly less capabilities and up to a 400x slowdown, with no improvement in safety? Of course you haven't, but with `runwasm` you can! `runwasm` is a shim for Emscripten-compiled wasm files that allows you to run them with [`wasmi`][wasmi]. It was mainly designed as a benchmarking system for `wasmi`, using the fact that the timing is done from _inside_ the binary to avoid testing startup costs (which we still want to benchmark, but in isolation). We had already written some custom tests that basically hand-rolled this technique with custom host functions, but doing it this way means we can essentially run most benchmarks unmodified.

[wasmi]: https://github.com/paritytech/wasmi

All you need to do is compile the binary, test or benchmarks for WebAssembly with Emscripten, like so:

```
cargo build --release --target=wasm32-unknown-emscripten
# or
cargo test --release --target=wasm32-unknown-emscripten
# or
cargo bench --target=wasm32-unknown-emscripten
```

It needs to be `--release` because otherwise you'll get some errors about undefined imports. In release mode these imports are removed by dead code elimination. Eventually I'll get around to defining all the imports, even the unused ones, but for now `--release` should work for many binaries.

Then you can find a `.js` and a `.wasm` file in `target/wasm32-unknown-emscripten/release/deps`. The `.js` file is runnable with `node`, and you'll see something similar to as if you had run it natively (although Emscripten implements a virtual filesystem). The only thing you'll need from the `.js` file to run the `.wasm` file with `runwasm` is the value of `STATIC_BUMP`. In the debug-mode builds it looks something like:

```js
var STATIC_BUMP = 48944;
```

But for the release builds the JavaScript is minified so you can do `rg -o 'STATIC_BUMP=\d+' path/to/file.js`. Then you can run:

```
runwasm --static-bump STATICBUMP path/to/file.wasm
```

Where STATICBUMP is the value that you got from the JS. If you want to pass arguments to the binary, just add them after the file, such as:

```
runwasm --static-bump STATICBUMP path/to/file.wasm -- --bench
```

For an example of the kind of slowdown you should expect, here's the benchmarks of `tiny-keccak` run natively:

```
running 2 tests
test bench_sha3_256_input_4096_bytes ... bench:      17,359 ns/iter (+/- 164) = 235 MB/s
test keccakf_u64                     ... bench:         548 ns/iter (+/- 9) = 45 MB/s

test result: ok. 0 passed; 0 failed; 0 ignored; 2 measured; 0 filtered out
```

Here's the same benchmarks run with `runwasm`:

```
running 2 tests
test bench_sha3_256_input_4096_bytes ... bench:   5,887,402 ns/iter (+/- 93,883)
test keccakf_u64                     ... bench:     157,583 ns/iter (+/- 1,683)

test result: ok. 0 passed; 0 failed; 0 ignored; 2 measured; 0 filtered out
```

Finally, the `cargo benchcmp` results to show the difference between these two:

```
 name                             native.bench ns/iter  wasm.bench ns/iter  diff ns/iter     diff %  speedup 
 bench_sha3_256_input_4096_bytes  17,359 (235 MB/s)     5,887,402              5,870,043  33815.56%   x 0.00 
 keccakf_u64                      548 (45 MB/s)         157,583                  157,035  28656.02%   x 0.00 
```
