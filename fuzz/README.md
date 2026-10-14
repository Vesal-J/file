# Fuzz Testing System for `uu_file`

This directory and the companion in-tree integration tests provide three layers of fuzz testing for `uu_file`:

---

## 1. Fast In-Tree Fuzz Suite (Stable Rust / CI)

No external tools or nightly toolchains required. Uses a deterministic PRNG and a Havoc-style mutator (bit flips, byte overwrites, chunk insertions, integer boundaries, dictionary tokens).

```bash
# Run with default iteration counts (2,000 iterations per target)
cargo test --test test_fuzz -- --nocapture

# Or scale up iterations for deep fuzzing:
FUZZ_ITERS=50000 FUZZ_MAGIC_ITERS=20000 cargo test --test test_fuzz -- --nocapture
```

### Targets covered:
- **`test_fuzz_classification_engine`**: Mutated payloads against `classify_buffer` in default, keep-going (`-k`), and uncompress (`-z`) modes.
- **`test_fuzz_magic_parser`**: Malformed magic rule grammars, indirect offsets, and regex expressions against `parse_magic_file`.
- **`test_fuzz_specialized_parsers`**: Targeted fuzzing on ELF, JSON/NDJSON, TAR, CSV, and CDF parsers.
- **`test_cve_regressions`**: Known historical CVE attacks (CVE-2014-1943 indirect recursion bombs, deep hierarchy nesting, huge search windows).

---

## 2. LLVM `cargo-fuzz` / `libfuzzer-sys` (Nightly / Continuous Fuzzing)

Uses LLVM's coverage-guided engine (`libFuzzer`) with AddressSanitizer and UndefinedBehaviorSanitizer instrumentation.

### Prerequisites:
```bash
cargo install cargo-fuzz
```

### Running Fuzz Targets:
```bash
cd file

# Fuzz the buffer classification engine:
cargo +nightly fuzz run fuzz_classify

# Fuzz the magic file syntax parser:
cargo +nightly fuzz run fuzz_magic_parser

# Differential mode testing invariants:
cargo +nightly fuzz run fuzz_diff
```

---

## 3. Differential Fuzzing against C `file` (`differential_fuzzer.py`)

A standalone differential fuzzer that executes mutated inputs simultaneously against Debian's `/usr/bin/file` and `uu_file`.

```bash
# Run 5,000 differential iterations:
python3 file/fuzz/differential_fuzzer.py 5000
```

### What it tracks:
- **C crashes**: Segfaults (`SIGSEGV`), aborts (`SIGABRT`), bus errors (`SIGBUS`) in upstream C `libmagic`.
- **Rust panics**: Unexpected `unwrap()` or index out-of-bounds.
- **Hangs / Timeouts**: Infinite loops or exponential search backtracking (> 2.0s).
- **Crashing inputs**: Automatically minimized and saved to `file/fuzz/crashes/<hash>.bin`.
