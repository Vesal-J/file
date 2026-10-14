# Comprehensive Specification, Analysis & Implementation Tasks: Rewriting Linux `file` in Rust

> **Target Standard**: Idiomatic, memory-safe, clean-room drop-in replacement matching the engineering excellence of `uutils` (e.g. `uutils/grep`) and full behavioral compatibility with `astron/file` (the reference implementation of Ian Darwin & Christos Zoulas).

---

## Table of Contents
1. [Core Objectives & Guiding Principles](#1-core-objectives--guiding-principles)
2. [Deep Architectural Analysis of the C Codebase (`c-file/src`)](#2-deep-architectural-analysis-of-the-c-codebase-c-filesrc)
3. [Exhaustive Flags & Command-Line Option Matrix](#3-exhaustive-flags--command-line-option-matrix)
4. [Engine Parameters & Tunables (`-P`)](#4-engine-parameters--tunables--p)
5. [The Exact Test Precedence Pipeline](#5-the-exact-test-precedence-pipeline)
6. [Historical Bugs, CVEs, and Vulnerability Analysis](#6-historical-bugs-cves-and-vulnerability-analysis)
7. [Subsystem Specifications & Rust Implementation Details](#7-subsystem-specifications--rust-implementation-details)
   - [7.1 Filesystem & Special Files (`fsmagic.c`)](#71-filesystem--special-files-fsmagicc)
   - [7.2 Encoding & Text Properties (`encoding.c`, `ascmagic.c`)](#72-encoding--text-properties-encodingc-ascmagicc)
   - [7.3 The Magic Compiler & Engine (`apprentice.c`, `softmagic.c`)](#73-the-magic-compiler--engine-apprenticec-softmagicc)
   - [7.4 Deep ELF Header Analysis (`readelf.c`)](#74-deep-elf-header-analysis-readelfc)
   - [7.5 Composite Document Files / CDF (`cdf.c`, `readcdf.c`)](#75-composite-document-files--cdf-cdfc-readcdfc)
   - [7.6 Structured Formats: Tar, JSON, CSV, DER/ASN.1](#76-structured-formats-tar-json-csv-derasn1)
   - [7.7 Transparent Decompression (`compress.c`)](#77-transparent-decompression-compressc)
   - [7.8 Sandboxing & Privilege Dropping (`seccomp.c`, `landlock.c`)](#78-sandboxing--privilege-dropping-seccompc-landlockc)
8. [Cross-Platform & Environmental Considerations](#8-cross-platform--environmental-considerations)
9. [Verification, Fuzzing & Testing Protocol](#9-verification-fuzzing--testing-protocol)
10. [Master Implementation Task Breakdown (Step-by-Step Roadmap)](#10-master-implementation-task-breakdown-step-by-step-roadmap)

---

## 1. Core Objectives & Guiding Principles

### 1.1 Objectives
1. **Drop-in Binary Replacement**: The compiled binary (`file`) must replicate all flags, outputs, exit codes, formatting idiosyncrasies, padding rules, and error messages of upstream `file(1)`.
2. **Library Crate Parity**: Provide an embeddable, safe Rust crate `uu_file` (and an optional C API mimicking `libmagic.so`) with zero unsafe code in the core engine.
3. **Absolute Memory & Execution Safety**: Eliminate the entire class of memory vulnerabilities that have plagued `libmagic` historically: out-of-bounds reads, heap/stack buffer overflows, integer overflows, infinite recursion loops, and denial-of-service via algorithmic complexity.
4. **Deterministic Output Across Environments**: Output must be independent of locale anomalies or local machine timezone variations (standardizing on UTC for embedded timestamps unless explicitly overridden).
5. **Clean-Room License Compliance**: Never copy, translate, or incorporate GPL or proprietary code directly. Follow POSIX IEEE Std 1003.1, `file(1)` and `magic(5)` documentation, public file format specifications, and BSD/MIT references.
6. **Blazing Fast Performance**: Meet or beat C `file` using zero-copy sliding buffer windows (`&[u8]`), fast SIMD byte searches, precompiled embedded magic tables, and thread-level parallelism (`rayon`) for batch scans.

---

## 2. Deep Architectural Analysis of the C Codebase (`c-file/src`)

The C implementation is divided between the command-line CLI frontend (`file.c`) and the `libmagic` engine (`magic.c` and underlying components). Here is the functional breakdown of every core file:

| C Source File | Core Responsibility in C Implementation | Rust Rewrite Mapping / Equivalent |
|---|---|---|
| `file.c` | CLI argument parsing (`getopt_long`), file list processing (`-f`), output alignment padding, exit status handling. | `src/lib.rs` (`uumain`), `clap` argument parsing, `uucore` error reporting. |
| `file_opts.h` | Table of short and long CLI flags, default values influenced by `POSIXLY_CORRECT`. | `src/lib.rs` (`uu_app()` definition). |
| `magic.c` | Public `libmagic` API: `magic_open`, `magic_load`, `magic_file`, `magic_buffer`, `magic_error`, parameter state. | `src/magic/mod.rs` (`MagicSession` struct, configuration state, public inspection APIs). |
| `magic.h.in` | Header defining `MAGIC_*` flags, bitmask modifiers, parameter constants (`MAGIC_PARAM_*`). | `src/config.rs` (`Flags`, `Parameters`, bitflags). |
| `funcs.c` | Core dispatcher (`file_buffer()`), orchestrates tests, manages string output buffers (`file_printf`), separator logic. | `src/engine.rs` (`Engine::classify_buffer()`, `OutputCollector`). |
| `fsmagic.c` | Filesystem inspection using `stat()` / `lstat()`: checks empty files, directories, character/block devices, FIFOs, symlinks, sockets. | `src/fs.rs` (`test_filesystem()`, safe Unix stat abstractions). |
| `apprentice.c` | `magic(5)` file parser and compiler. Compiles text rules into binary `.mgc` files, validates syntax, calculates rule strength, sorts rule hierarchy. | `src/magic/parser.rs` & `src/magic/compiler.rs` (build-time / run-time parser into zero-copy bytecode). |
| `softmagic.c` | The Magic Virtual Machine. Evaluates compiled magic rules against input buffer, resolves offsets (direct, indirect, relative), evaluates comparisons, prints interpolated messages. | `src/magic/evaluator.rs` (VM evaluating AST rules over `&[u8]`). |
| `encoding.c` | Character set detection: scans buffer for ASCII, ISO-8859-x, UTF-8 (BOM or validation), UTF-16LE/BE, UTF-32LE/BE, EBCDIC. | `src/text/encoding.rs` (fast zero-alloc charset sniffer). |
| `ascmagic.c` | ASCII text inspection: scans for programming languages (C, Fortran, Pascal, Python), shebang scripts (`#!`), markup (HTML, XML, SGML), troff, mail, news. | `src/text/ascmagic.rs` (language keyword token matcher & shebang parser). |
| `readelf.c` / `elfclass.h` | Specialized deep ELF parser: extracts architecture, 32/64-bit, endianness, OS ABI, shared object vs executable vs core, program headers (`phnum`), section headers (`shnum`), notes, build ID, interpreter path, stripped state. | `src/specialized/elf.rs` (safe zero-copy ELF parsing, strictly bounds-checked). |
| `cdf.c` / `readcdf.c` / `cdf_time.c` | Microsoft Composite Document File (OLE2 structured storage) parser: parses directory streams, FAT chains, property sets for Word, Excel, PowerPoint, MSI installers, Thumbs.db. | `src/specialized/cdf.rs` (safe OLE2 stream navigator). |
| `compress.c` | Transparent decompression engine: detects gzip, bzip2, xz, lzma, zstd, compress (.Z), lz4, and evaluates nested contents. In C, it often forks child decompressors. | `src/decompress.rs` (in-memory streaming decompression using pure-Rust crates: `flate2`, `bzip2`, `xz2`, `zstd`). |
| `is_tar.c` | Detects POSIX ustar, GNU tar, old V7 tar archives by checking headers and checksums. | `src/specialized/tar.rs`. |
| `is_json.c` | Validates whether a file begins with valid JSON structures (`{...}`, `[...]`, or JSON lines). | `src/specialized/json.rs` (lightweight streaming JSON sniffer). |
| `is_csv.c` | Heuristic sniffer for CSV and TSV tabular text files. | `src/specialized/csv.rs`. |
| `is_simh.c` | Detects SIMH tape container images. | `src/specialized/simh.rs`. |
| `der.c` | ASN.1 DER certificate and cryptographic object decoder. | `src/specialized/der.rs`. |
| `apptype.c` | Windows and OS/2 executable header details (NE, LE, LX, PE). | `src/specialized/apptype.rs`. |
| `seccomp.c` / `landlock.c` | System call filtering via `seccomp-bpf` and filesystem sandboxing via Linux `Landlock`. | `src/sandbox.rs` (OS privilege dropping). |
| `print.c` | Debug printing of parsed magic rules (`file_mdump()`), octal/escaped string rendering. | `src/magic/debug.rs`. |

---

## 3. Exhaustive Flags & Command-Line Option Matrix

All flags from `c-file/src/file_opts.h` and `file.c` must be precisely supported:

### 3.1 Primary Output & Control Flags
| Short | Long | Takes Param | Description & Behavioral Specifics |
|---|---|---|---|
| `-b` | `--brief` | No | Brief mode: suppresses prepending the filename to output lines. |
| `-i` | `--mime` | No | Causes `file` to output MIME type strings instead of human-readable text. Shorthand for `--mime-type --mime-encoding`. |
| | `--mime-type` | No | Output MIME type string only (e.g. `application/x-pie-executable`, `text/plain`). |
| | `--mime-encoding` | No | Output MIME charset encoding only (e.g. `binary`, `us-ascii`, `utf-8`). |
| | `--apple` | No | Output Apple 8-character code: 4-character creator followed by 4-character type (fallback is `UNKNUNKN`). |
| | `--extension` | No | Output slash-separated list of valid file extensions (e.g. `jpeg/jpg/jpe/jfif`). Fallback is `???`. |
| `-k` | `--keep-going` | No | Don't stop at first match. Continues evaluating all tests and prints matches separated by `\n- `. |
| `-c` | `--checking-printout` | No | Parses the magic database and prints its internal representation to stdout for debugging syntax before installation. |
| `-C` | `--compile` | No | Pre-compiles the text magic files into a binary `.mgc` database file and exits. |
| `-d` | `--debug` | No | Prints verbose internal debugging messages to stderr during execution. |
| `-v` | `--version` | No | Prints version information and magic file path, then exits with code 0. |
| | `--help` | No | Displays detailed usage and help text, then exits with code 0. |

### 3.2 File Handling, Input & Separator Flags
| Short | Long | Takes Param | Description & Behavioral Specifics |
|---|---|---|---|
| `-f` | `--files-from` | `FILE` | Read the filenames to examine from `FILE` (one per line). If `FILE` is `-`, read list from standard input. Empty lines are ignored. |
| `-F` | `--separator` | `STRING` | Use `STRING` as the separator between the filename and the file result (default is `:`). |
| `-0` | `--print0` | No | Output a null character `\0` after the filename instead of a separator and space (ideal for pairing with `xargs -0`). |
| `-n` | `--no-buffer` | No | Flush stdout after checking each file (ensures immediate output when piping). |
| `-N` | `--no-pad` | No | Do not pad output filenames to align results across multiple inputs. |
| `-r` | `--raw` | No | Do not translate unprintable/control characters into octal escapes (`\ooo`). |
| `-p` | `--preserve-date` | No | Attempt to restore the file's access time (`atime`) after reading. |
| `-s` | `--special-files` | No | Treat special block and character devices as ordinary files (opens and reads their raw data rather than reporting their device status). |
| `-S` | `--no-sandbox` | No | Disable OS sandboxing (`seccomp` / `landlock`). |

### 3.3 Symlink Behavior (POSIX Nuance)
| Short | Long | Default Logic (`POSIXLY_CORRECT`) |
|---|---|---|
| `-L` | `--dereference` | Follow symlinks. **Default if `POSIXLY_CORRECT` environment variable is set.** |
| `-h` | `--no-dereference` | Do not follow symlinks; describe the symlink itself. **Default if `POSIXLY_CORRECT` is NOT set.** |

### 3.4 Decompression Flags
| Short | Long | Description |
|---|---|---|
| `-z` | `--uncompress` | Try to look inside compressed files (gzip, bzip2, xz, zstd, etc.) and report both compression and inner content. |
| `-Z` | `--uncompress-noreport` | Look inside compressed files, but report only the decompressed content without mentioning compression. |

### 3.5 Test Exclusion Flags (`-e` / `--exclude`)
Allows disabling specific built-in tests (can be specified multiple times):
* `apptype`: Check for EMX OS/2 application types.
* `ascii`: Check for various text file formats and encodings.
* `cdf`: Check for Composite Document Files (OLE2).
* `compress`: Check for and look inside compressed files.
* `csv`: Check for Comma-Separated Value files.
* `elf`: Check for ELF binary details.
* `encoding`: Check for text character encodings.
* `soft`: Check magic file database rules.
* `tar`: Check for tar archives.
* `json`: Check for JSON data files.
* `simh`: Check for SIMH tape images.
* `--exclude-quiet`: Like `--exclude`, but ignores unrecognized test names without throwing an error.

---

## 4. Engine Parameters & Tunables (`-P`)

Upstream `file` provides the `-P <parameter=value>` flag to limit resource consumption. The Rust rewrite must support all ten tunables:

| Parameter Name | Default in C (`file.h`) | Purpose & Security Constraint |
|---|---|---|
| `bytes` | `7 * 1024 * 1024` (7 MiB) | Maximum bytes read from input file into inspection buffer. Prevents unbounded memory reads. |
| `indir` | `50` | Maximum recursion limit for indirect magic rule offsets (`(offset.type)`). Prevents infinite loops. |
| `name` | `150` | Maximum call limit for `use` / `name` subroutine rules. Prevents call graph recursion loops. |
| `elf_notes` | `256` | Maximum number of ELF notes processed. Prevents DoS on corrupted ELF headers. |
| `elf_phnum` | `2,048` | Maximum number of ELF program section headers scanned. |
| `elf_shnum` | `32,768` | Maximum number of ELF section headers scanned. |
| `elf_shsize` | `128 * 1024 * 1024` (128 MiB) | Maximum cumulative ELF section header size. |
| `encoding` | `64 * 1024` (64 KiB) | Maximum bytes scanned during charset/text encoding determination. |
| `regex` | `8,192` | Maximum byte length scanned during regex pattern matching. |
| `magwarn` | `64` | Maximum number of warnings emitted while compiling/loading magic rules before aborting. |

---

## 5. The Exact Test Precedence Pipeline

The Rust engine must follow the exact evaluation order implemented in `funcs.c::file_buffer()`:

```
                         [ Start: Input File ]
                                   │
              ┌────────────────────▼────────────────────┐
              │ 1. Filesystem Tests (fsmagic)           │
              │    - S_ISDIR  -> "directory"            │
              │    - S_ISLNK  -> "symbolic link to ..." │
              │    - S_ISCHR  -> "character special"    │
              │    - S_ISBLK  -> "block special"        │
              │    - S_ISFIFO -> "fifo (named pipe)"    │
              │    - S_ISSOCK -> "socket"               │
              │    - stat.st_size == 0 -> "empty"       │
              └────────────────────┬────────────────────┘
                                   │ (Regular file with size > 0)
              ┌────────────────────▼────────────────────┐
              │ 2. Read Bounded Buffer (up to -P bytes) │
              │    - if len == 1: "very short file"     │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │ 3. Character Encoding Sniffer           │
              │    - UTF-8, UTF-16LE/BE, ASCII, etc.    │
              │    - Sets looks_text and code_mime      │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │ 4. Decompression (-z flag / zmagic)     │
              │    - Decompress gzip/bzip2/xz/zstd      │
              │    - Substitute buffer if decompressed  │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │ 5. Structured Format Built-in Tests     │
              │    a. is_tar()                          │
              │    b. is_json()                         │
              │    c. is_csv()                          │
              │    d. is_simh()                         │
              │    e. trycdf() (Composite Doc / OLE2)   │
              │    f. tryelf() (Extract ELF details)    │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │ 6. Soft Magic Database Evaluation       │
              │    - Evaluate compiled magic rules      │
              │    - If matched ELF, append ELF details │
              │    - If match found & not -k: STOP      │
              └────────────────────┬────────────────────┘
                                   │ (No magic match)
              ┌────────────────────▼────────────────────┐
              │ 7. ASCII / Text Properties (ascmagic)   │
              │    - Shebang parsing (#!/bin/sh)        │
              │    - Script & programming languages     │
              │    - Markup (HTML, XML, SGML)           │
              └────────────────────┬────────────────────┘
                                   │ (No text match)
              ┌────────────────────▼────────────────────┐
              │ 8. Fallback Default                     │
              │    - Output: "data"                     │
              │    - MIME: "application/octet-stream"   │
              └─────────────────────────────────────────┘
```

---

## 6. Historical Bugs, CVEs, and Vulnerability Analysis

A thorough audit of `ChangeLog`, `NEWS`, and historical security advisories across 20+ years of `file` development reveals the primary failure modes in C:

### 6.1 Vulnerability Catalog

1. **CVE-2014-1943 (Infinite Recursion in Indirect Offsets)**:
   * *Mechanism*: A crafted magic file or input binary directed the indirect offset evaluator to recursively read from offset 0, causing infinite recursion and stack exhaustion.
   * *Rust Solution*: Track recursion depth explicitly with an accumulator and bail out if `depth > config.indir_max`.
2. **CVE-2014-8116 & CVE-2014-8117 (ELF Notes and Program Headers DoS)**:
   * *Mechanism*: Corrupt ELF files specifying tens of thousands of zero-length notes or invalid segment counts caused massive allocation and loops.
   * *Rust Solution*: Strictly enforce limits (`elf_notes_max`, `elf_phnum_max`, `elf_shnum_max`) and validate offsets before seeking.
3. **CVE-2019-18218 (CDF Out-of-Bounds Read in Sector Allocation)**:
   * *Mechanism*: Corrupt sector chain tables in OLE2/CDF files led to integer overflow in allocation calculations, causing heap buffer over-reads.
   * *Rust Solution*: Use checked integer arithmetic (`checked_add`, `checked_mul`) and Rust slice indexing (`buf.get(range)`).
4. **Pascal String Buffer Over-read**:
   * *Mechanism*: In Pascal strings (`pstring`), the first byte specifies length $N$. If $N$ extends past the buffer end, C `file` read arbitrary adjacent heap memory.
   * *Rust Solution*: Validate that `offset + 1 + length <= buffer.len()`; truncate or fail if the length exceeds remaining bytes.
5. **ReDoS (Regular Expression Denial of Service)**:
   * *Mechanism*: Pathological regexes in magic files combined with crafted input text triggered exponential backtracking in PCRE/POSIX regex engines.
   * *Rust Solution*: Use Rust's DFA-based `regex` engine, which guarantees $O(n)$ linear execution time.
6. **FIFO / Special File Hang**:
   * *Mechanism*: Invoking `file` on a named pipe (`mkfifo mypipe; file mypipe`) would block the process forever waiting on a writer.
   * *Rust Solution*: Always open files with `O_NONBLOCK`. Query file metadata first; never read a FIFO unless `-s` is explicitly given.
7. **Timezone Variation Flaws**:
   * *Mechanism*: Upstream tests produced different timestamp outputs depending on the developer's local timezone.
   * *Rust Solution*: Format all embedded timestamps in UTC by default, ensuring byte-for-byte reproducibility.

---

## 7. Subsystem Specifications & Rust Implementation Details

### 7.1 Filesystem & Special Files (`fsmagic.c`)
* Use `nix::sys::stat::lstat` or `std::fs::symlink_metadata`.
* Special file detection:
  * Directory: `"directory"`
  * Character device: `"character special (major/minor)"`
  * Block device: `"block special (major/minor)"`
  * FIFO: `"fifo (named pipe)"`
  * Socket: `"socket"`
  * Symlink (when `-h`): `"symbolic link to <target>"`
  * Broken symlink (when `-L`): `"broken symbolic link to <target>"`
* Empty file: when `st_size == 0`, report `"empty"`.

### 7.2 Encoding & Text Properties (`encoding.c`, `ascmagic.c`)
* **Encoding Detection Order**:
  1. Check for UTF-8 Byte Order Mark (BOM `0xEF 0xBB 0xBF`).
  2. Check for UTF-16LE (`0xFF 0xFE`) and UTF-16BE (`0xFE 0xFF`) BOMs.
  3. Check for UTF-32LE (`0xFF 0xFE 0x00 0x00`) and UTF-32BE (`0x00 0x00 0xFE 0xFF`).
  4. Validate UTF-8 compliance across the opening chunk (up to `encoding_max`). If valid and non-ASCII, tag as `utf-8`.
  5. Check if all bytes are in the printable ASCII range (`0x07..=0x0D`, `0x20..=0x7E`).
  6. Fall back to ISO-8859-1 or extended 8-bit text.
* **ASCII Text Heuristics**:
  * Shebang: Match `^#!\s*(\S+)`. Extract script interpreter name (e.g. `python`, `perl`, `sh`, `bash`, `node`).
  * Keywords: Search for language indicators:
    * C: `/*`, `#include`, `static `, `extern `
    * C++: `//`, `class `, `template<`, `namespace `
    * Python: `def `, `import `, `class `, `print(`
    * HTML: `<!DOCTYPE html`, `<html`, `<body`
    * XML: `<?xml `

### 7.3 The Magic Compiler & Engine (`apprentice.c`, `softmagic.c`)
The magic engine is a domain-specific bytecode virtual machine.
* **Rule Syntax**:
  ```text
  [level]offset  type  [operator]value  message
  ```
* **Supported Types**:
  * Numerics: `byte`, `short`, `long`, `quad`, `float`, `double` (with endian variants `le*`, `be*`, `me*`).
  * Strings: `string`, `pstring`, `search`, `regex`.
  * Dates: `date`, `qdate`, `ldate` (formatted as UTC timestamps).
  * Directives: `name`, `use` (subroutines), `indirect` (computed jumps).
  * Modifiers: `!:mime <type>`, `!:ext <extensions>`, `!:strength [+-]<val>`, `!:apple <creator/type>`.
* **Zero-Copy Bytecode**:
  Compile text rules into a contiguous flat vector of AST nodes at build time (`build.rs`). Embed the compiled database into the binary via `include_bytes!`.

### 7.4 Deep ELF Header Analysis (`readelf.c`)
* ELF inspection provides rich metadata that cannot be described by simple magic rules alone:
  * Header validation (`\x7fELF`).
  * Bit class: 32-bit (`ELFCLASS32`) or 64-bit (`ELFCLASS64`).
  * Endianness: Little-endian (`ELFDATA2LSB`) or Big-endian (`ELFDATA2MSB`).
  * Type: Relocatable (`ET_REL`), Executable (`ET_EXEC`), Shared Object / PIE (`ET_DYN`), Core Dump (`ET_CORE`).
  * OS ABI: System V, Linux, FreeBSD, NetBSD, Solaris, etc.
  * Program Headers: Scan for `PT_INTERP` (extract dynamic linker path, e.g. `/lib64/ld-linux-x86-64.so.2`).
  * Notes: Scan `SHT_NOTE` for `GNU_BUILD_ID` and OS versions.
  * Stripped status: Check if section header table (`shnum == 0`) or symbol table is missing.

### 7.5 Composite Document Files / CDF (`cdf.c`, `readcdf.c`)
* Microsoft OLE2 structured storage used in legacy Microsoft Office files (`.doc`, `.xls`, `.ppt`), `.msi` installers, and Windows `.reg` files.
* Parse the 512-byte header, traverse the Sector Allocation Table (SAT), read the Directory stream, and extract property streams (`SummaryInformation`):
  * Application name (e.g. `Microsoft Office Word`).
  * Title, Author, Revision Number.
  * Template name and edit timestamps.

### 7.6 Structured Formats: Tar, JSON, CSV, DER/ASN.1
* **Tar**: Verify checksum in the 512-byte header:
  $$\text{checksum} = \sum_{i=0}^{511} \text{byte}_i \quad (\text{with checksum field treated as spaces})$$
* **JSON**: Fast streaming parser checks for valid object `{...}`, array `[...]`, or newline-delimited JSON.
* **CSV/TSV**: Verify consistent delimiter counts across the first $N$ lines.

### 7.7 Transparent Decompression (`compress.c`)
* When `-z` or `-Z` is enabled:
  * Detect compression header:
    * Gzip: `1f 8b`
    * Bzip2: `42 5a 68` (`BZh`)
    * XZ: `fd 37 7a 58 5a 00`
    * Zstandard: `28 b5 2f fd`
    * Compress: `1f 9d`
  * Stream decompressed output into a capped memory buffer (max 1 MiB).
  * Run the full inspection pipeline recursively on the decompressed buffer.

### 7.8 Sandboxing & Privilege Dropping (`seccomp.c`, `landlock.c`)
* Support optional Linux seccomp-bpf filtering:
  * After initial initialization and opening target file descriptors, drop process capabilities.
  * Restrict permitted syscalls to `read`, `write`, `fstat`, `close`, and `exit_group`.
  * Disable via `-S` / `--no-sandbox`.

---

## 8. Cross-Platform & Environmental Considerations

1. **Path Handling & Separators**: Use `std::path::Path` to seamlessly handle `/` on Unix and `\` on Windows.
2. **Terminal Padding (`-N` vs default)**: In multi-file mode, `file` calculates the maximum filename length across the input list and pads output lines with spaces so descriptions align vertically. Match this behavior.
3. **Escaping Unprintable Characters (`-r` vs default)**: By default, control and non-ASCII bytes in filenames and output messages must be formatted as octal escapes `\ooo`. When `-r` is given, print raw bytes.
4. **Timezones**: Set time evaluation to UTC to guarantee tests pass consistently regardless of local host timezone.

---

## 9. Verification, Fuzzing & Testing Protocol

Replicating the quality assurance standards of `uutils/grep`:

```
┌────────────────────────────────────────────────────────┐
│ Tier 1: Unit Tests (Encoding, AST, Bytecode, Offsets)  │
├────────────────────────────────────────────────────────┤
│ Tier 2: CLI Integration Tests (tests/test_file.rs)      │
│         - Testing flags: -b, -i, -k, -z, -F, -0, -L/-h │
├────────────────────────────────────────────────────────┤
│ Tier 3: Upstream Regression Suite (tests/*.testfile)   │
│         - 100+ test fixtures from astron/file verified │
├────────────────────────────────────────────────────────┤
│ Tier 4: Differential Fuzzing (fuzz/fuzz_file.rs)       │
│         - Rust output compared directly to C file      │
├────────────────────────────────────────────────────────┤
│ Tier 5: Performance Benchmarks (CodSpeed + Criterion)  │
│         - Microbenchmarks on 10,000 mixed files        │
└────────────────────────────────────────────────────────┘
```

---

## 10. Master Implementation Task Breakdown (Step-by-Step Roadmap)

### Phase 1: Project Setup & CLI Harness
- [ ] **Task 1.1**: Initialize `Cargo.toml` with dual-target structure (`uu_file` lib + `file` bin), MSRV 1.88.0, and 2024 edition.
- [ ] **Task 1.2**: Wire `src/main.rs` using `uucore::bin!(uu_file)`.
- [ ] **Task 1.3**: Define the complete `clap` CLI interface in `src/lib.rs` matching all flags from `file_opts.h`.
- [ ] **Task 1.4**: Configure `.pre-commit-config.yaml`, `dist-workspace.toml`, and `.cargo/config.toml`.
- [ ] **Task 1.5**: Implement `-f <filelist>` and `-` (stdin) reading logic with `-0` delimiter support.

### Phase 2: Filesystem & Encoding Engines
- [ ] **Task 2.1**: Implement `src/fs.rs` for `stat()` inspection (devices, FIFOs, sockets, directories, symlinks, empty files).
- [ ] **Task 2.2**: Implement `-L` vs `-h` symlink dereferencing based on `POSIXLY_CORRECT`.
- [ ] **Task 2.3**: Implement `src/text/encoding.rs` for BOM and UTF-8/UTF-16/ASCII detection.
- [ ] **Task 2.4**: Implement `src/text/ascmagic.rs` for shebang line extraction and programming language token matching.

### Phase 3: The Magic Compiler & Virtual Machine
- [ ] **Task 3.1**: Implement `src/magic/ast.rs` representing the hierarchical `magic(5)` rule AST.
- [ ] **Task 3.2**: Implement `src/magic/parser.rs` capable of parsing standard `Magdir/*` rule definitions.
- [ ] **Task 3.3**: Implement `src/magic/evaluator.rs`:
  - Numeric comparisons (`byte`, `short`, `long`, `quad`, with endian swaps).
  - String comparisons, Pascal strings, search windows, and regex.
  - Direct, relative (`&`), and indirect (`(...)`) offsets.
  - Subroutine calls (`name` / `use`) with bounded recursion.
- [ ] **Task 3.4**: Implement `build.rs` to precompile curated magic rules into a binary database embedded via `include_bytes!`.

### Phase 4: Specialized Deep Parsers
- [ ] **Task 4.1**: Implement `src/specialized/elf.rs` (32/64-bit, endianness, interpreter, build ID, stripped status).
- [ ] **Task 4.2**: Implement `src/specialized/tar.rs` (POSIX ustar and GNU tar header verification).
- [ ] **Task 4.3**: Implement `src/specialized/json.rs` and `src/specialized/csv.rs`.
- [ ] **Task 4.4**: Implement `src/specialized/cdf.rs` (OLE2 structured storage for Word, Excel, PowerPoint).
- [ ] **Task 4.5**: Implement `src/decompress.rs` for `-z` / `-Z` transparent decompression (gzip, bzip2, xz, zstd).

### Phase 5: Formatting, Padding & Output Parity
- [ ] **Task 5.1**: Implement `src/output.rs`:
  - Standard mode (`filename: result`).
  - Brief mode (`-b`).
  - Custom separator (`-F`).
  - MIME mode (`-i`, `--mime-type`, `--mime-encoding`).
  - Extensions mode (`--extension`).
  - Apple creator/type mode (`--apple`).
  - Continuous match mode (`-k`).
- [ ] **Task 5.2**: Implement dynamic terminal padding across multi-file runs (`-N` to disable).
- [ ] **Task 5.3**: Implement octal character escaping for control bytes (`-r` to disable).

### Phase 6: Testing, Upstream Verification & CI
- [ ] **Task 6.1**: Implement CLI integration tests in `tests/test_cli.rs` using `uutests`.
- [ ] **Task 6.2**: Port the upstream `tests/*.testfile` suite and verify byte-for-byte output matching.
- [ ] **Task 6.3**: Implement differential fuzzing in `fuzz/fuzz_targets/fuzz_file.rs` comparing against system `file`.
- [ ] **Task 6.4**: Set up Criterion benchmarks in `benches/file_bench.rs` with CodSpeed integration.
- [ ] **Task 6.5**: Create GitHub Actions workflows (`ci.yml`, `code-quality.yml`, `fuzzing.yml`).
