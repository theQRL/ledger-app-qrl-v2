# Fuzzing on transaction parser

## Fuzzing

Fuzzing allows us to test how a program behaves when provided with invalid, unexpected, or random data as input.

In the case of this app we want to test the code that is responsible for parsing the transaction data,
which is the streaming RLP parser in `src/tx_stream.c` (`tx_stream_feed()`).
Our fuzz target, `fuzz_tx_parser.c`, implements `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`:
the first input byte selects the chunk size and the remaining bytes are fed to the parser chunk by chunk,
the same way the transaction reaches the device over several APDUs.
If the application crashes, or a [sanitizer](https://github.com/google/sanitizers) detects any kind of
access violation, the fuzzing process is stopped, a report regarding the vulnerability is shown,
and the input that triggered the bug is written to disk under the name `crash-*`.
The vulnerable input file created can be passed as an argument to the fuzzer to triage the issue.

> **Note**: Usually we want to write a separate fuzz target for each functionality.
> `fuzz_tx_format.c` is a second target for the amount / fee display formatters in `src/ui/tx_format.c`.

## Manual usage based on Ledger container

### Preparation

The fuzzer builds in the regular `ledger-app-dev-tools` image. That image ships clang but not the
libFuzzer / sanitizer runtime, so install it once inside the container (this needs root, hence no `--user`):

```console
docker run --rm -ti -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest

# inside the container (adjust 21 to the clang major version reported by `clang --version`)
apt-get update && apt-get install -y libclang-rt-21-dev
D=$(clang -print-runtime-dir); mkdir -p "$D"
for f in /usr/lib/llvm-21/lib/clang/21/lib/linux/libclang_rt.*-x86_64.a; do
    b=$(basename "$f"); ln -sf "$f" "$D/${b/-x86_64/}"
done
```

> **Note**: the `ledger-app-builder-legacy` image has the runtime preinstalled, but it is several GB larger.

### Compilation

Once in the container, configure and build with clang. The parser is SDK-free, so no `BOLOS_SDK` is needed.
Building in a directory outside the mounted repository (as below) avoids leaving root-owned files in it:

```console
cmake -DCMAKE_C_COMPILER=clang -B/tmp/fuzz-build -H/app/fuzzing
make -C /tmp/fuzz-build
```

### Run

```console
# optional: a directory of seed inputs; new interesting inputs are added to it
/tmp/fuzz-build/fuzz_tx_parser -max_total_time=60 -max_len=8192 /app/fuzzing/corpus
```

A finding is reported with a sanitizer stack trace and the triggering input is saved as `crash-*`
in the current directory; pass that file as the only argument to reproduce it.

## Full usage based on `clusterfuzzlite` container

Exactly the same context as the CI, directly using the `clusterfuzzlite` environment.

More info can be found here:
<https://google.github.io/clusterfuzzlite/>

### Preparation

The principle is to build the container, and run it to perform the fuzzing.

> **Note**: The container contains a copy of the sources (they are not cloned),
> which means the `docker build` command must be re-executed after each code modification.

```console
# Prepare directory tree
mkdir fuzzing/{corpus,out}
# Container generation
docker build -t app-boilerplate --file .clusterfuzzlite/Dockerfile .
```

### Compilation

```console
docker run --rm --privileged -e FUZZING_LANGUAGE=c -v "$(realpath .)/fuzzing/out:/out" -ti app-boilerplate
```

### Run

```console
docker run --rm --privileged -e FUZZING_ENGINE=libfuzzer -e RUN_FUZZER_MODE=interactive -v "$(realpath .)/fuzzing/corpus:/tmp/fuzz_corpus" -v "$(realpath .)/fuzzing/out:/out" -ti gcr.io/oss-fuzz-base/base-runner run_fuzzer fuzz_tx_parser
```
