# file (uutils)

A clean-room, production-grade, memory-safe, drop-in replacement for the Linux `file` command in Rust, architected to match the engineering standards of the `uutils` ecosystem (e.g. `uutils/grep`).

## Features

- **Drop-in Compatibility**: Replicates flags, outputs, and exit codes of upstream `file(1)` / `libmagic`.
- **Memory Safety**: Clean-room implementation in safe Rust, hardened against ReDoS, buffer overflows, infinite recursion loops, and decompression bombs.
- **Dual-Crate Architecture**: Provides both the core library crate `uu_file` and the standalone `file` binary.
- **7-Phase Test Pipeline**:
  1. Filesystem inspection (`stat`/`lstat`, devices, symlinks, FIFOs, sockets, empty files)
  2. Bounded header window inspection (up to `-P bytes`, default 7 MiB)
  3. Transparent streaming decompression (`-z` / `-Z` for gzip, bzip2, xz, zstd)
  4. Specialized deep parsers (ELF, Tar, JSON, CSV, CDF / OLE2)
  5. Magic rule engine (`magic(5)` parser & bytecode VM) + zero-copy fast-path tables
  6. Text & character encoding inspection (ASCII, UTF-8, UTF-16, ISO-8859, shebang lines, source code tokens)
  7. Deterministic fallback to binary `data`
- **Output Flexibility**: Supports Brief (`-b`), MIME (`-i`, `--mime-type`, `--mime-encoding`), Apple codes (`--apple`), Extensions (`--extension`), custom separators (`-F`), print0 (`-0`), and column alignment padding (`-N` to disable).

## Installation

```bash
cargo build --release
```

## Usage

```bash
# Basic inspection
file myfile.txt

# Brief mode (omit filename)
file -b myfile.txt

# MIME type and encoding
file -i myfile.txt
file --mime-type -b myfile.py

# Reading filenames from a list or standard input
file -f list.txt
find . -type f | file -f -

# Look inside compressed files
file -z archive.tar.gz
```

## License

Licensed under the MIT License.
