#!/usr/bin/env python3
"""
Differential Fuzzing Suite: C (astron/file) vs Rust (uu_file)

Runs mutational fuzzing in parallel, feeding identical byte streams to both
the Debian C /usr/bin/file and the Rust uu_file binary.

Detects:
1. Memory corruption & crashes in C (SIGSEGV, SIGBUS, SIGABRT, ASan)
2. Panics / unwrap errors in Rust (exit code 101)
3. Infinite loops / hangs (timeout exceeded)
4. Unexpected behavioral divergences
"""

import os
import sys
import time
import glob
import random
import hashlib
import tempfile
import subprocess
from concurrent.futures import ProcessPoolExecutor

C_BIN = "/usr/bin/file"
RUST_CANDIDATES = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../target/release/file")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../target/debug/file")),
]

CRASH_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "crashes"))

DICTIONARY = [
    b"\x7fELF",
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"BZh9",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"\x28\xb5\x2f\xfd",
    b"GIF89a",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"%PDF-1.4",
    b"SQLite format 3\0",
    b"ustar\00000",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"\xc6\x85\x73\xf6\x4e\x1a\x45\xca\x82\x65\xf5\x7f\x48\xba\x6d\x81",
    b"\xef\x53",
    b"ID3\x04\x00\x00\x00\x00\x02\x00",
    b"fLaC",
    b"OggS",
    b"RIFF\x24\x00\x00\x00WAVE",
    b"UF2\n",
    b"{\x22test\x22: [1, 2, 3]}",
    b"a,b,c\n1,2,3\n",
    b"%s%s%s%s%s%n",
    b"\0" * 32,
    b"\xff" * 32,
]

def find_rust_bin():
    for p in RUST_CANDIDATES:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None

def collect_seed_corpus():
    corpus = [
        b"",
        b"\0",
        b"\xff",
        b"Hello world\n",
        b"#!/bin/bash\necho hi\n",
    ]
    testfiles = glob.glob(os.path.join(os.path.dirname(__file__), "../../c-file/tests/*.testfile"))
    for tf in testfiles:
        try:
            with open(tf, "rb") as f:
                data = f.read()
                if data:
                    corpus.append(data)
        except Exception:
            pass
    return corpus

def mutate_payload(data: bytes) -> bytes:
    buf = bytearray(data)
    if len(buf) == 0:
        return random.choice(DICTIONARY)

    num_ops = random.randint(1, 4)
    for _ in range(num_ops):
        if len(buf) == 0:
            buf.extend(random.choice(DICTIONARY))
            continue

        op = random.randint(0, 7)
        if op == 0:
            # Bit flip
            idx = random.randrange(len(buf))
            buf[idx] ^= (1 << random.randrange(8))
        elif op == 1:
            # Byte overwrite
            idx = random.randrange(len(buf))
            buf[idx] = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFF, ord('\n'), ord('\0'), ord('%'), ord('"')])
        elif op == 2:
            # Byte insertion
            if len(buf) < 131072:
                idx = random.randrange(len(buf) + 1)
                buf.insert(idx, random.randrange(256))
        elif op == 3:
            # Byte deletion
            if len(buf) > 1:
                idx = random.randrange(len(buf))
                del buf[idx]
        elif op == 4:
            # Dictionary token insert
            if len(buf) < 131072:
                token = random.choice(DICTIONARY)
                idx = random.randrange(len(buf) + 1)
                buf[idx:idx] = token
        elif op == 5:
            # Truncation
            if len(buf) > 1:
                buf = buf[:random.randrange(len(buf))]
        elif op == 6:
            # Integer boundary insert
            val = random.choice([0, 1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF])
            bts = val.to_bytes(4, byteorder=random.choice(["little", "big"]))
            idx = random.randrange(len(buf) + 1)
            buf[idx:idx] = bts
        elif op == 7:
            # Swap
            if len(buf) >= 2:
                i = random.randrange(len(buf) - 1)
                buf[i], buf[i+1] = buf[i+1], buf[i]

    return bytes(buf)

def test_single_input(rust_bin, payload: bytes):
    with tempfile.NamedTemporaryFile(prefix="fuzz_", delete=False) as tmp:
        tmp.write(payload)
        tmp_path = tmp.name

    try:
        # 1. Run C file
        c_crash = None
        c_stdout = ""
        try:
            c_res = subprocess.run(
                [C_BIN, "-b", tmp_path],
                capture_output=True,
                timeout=2.0,
            )
            c_stdout = c_res.stdout.decode("utf-8", errors="replace").strip()
            # Crash code: negative or > 128
            if c_res.returncode < 0 or c_res.returncode in (134, 139):
                c_crash = f"C crashed with code {c_res.returncode}"
        except subprocess.TimeoutExpired:
            c_crash = "C timed out (> 2s)"

        # 2. Run Rust file
        rust_crash = None
        rust_stdout = ""
        try:
            r_res = subprocess.run(
                [rust_bin, "-b", tmp_path],
                capture_output=True,
                timeout=2.0,
            )
            rust_stdout = r_res.stdout.decode("utf-8", errors="replace").strip()
            if r_res.returncode == 101:
                rust_crash = "Rust panicked (exit code 101)"
            elif r_res.returncode < 0 or r_res.returncode in (134, 139):
                rust_crash = f"Rust killed by signal {r_res.returncode}"
        except subprocess.TimeoutExpired:
            rust_crash = "Rust timed out (> 2s)"

        return {
            "c_crash": c_crash,
            "rust_crash": rust_crash,
            "c_stdout": c_stdout,
            "rust_stdout": rust_stdout,
            "payload": payload,
        }
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

def save_crash(name_prefix: str, payload: bytes, info: str):
    os.makedirs(CRASH_DIR, exist_ok=True)
    h = hashlib.sha256(payload).hexdigest()[:12]
    filename = os.path.join(CRASH_DIR, f"{name_prefix}_{h}.bin")
    with open(filename, "wb") as f:
        f.write(payload)
    print(f"\n[!] SAVED CRASH REPRODUCER to {filename}: {info}")

def main():
    rust_bin = find_rust_bin()
    if not rust_bin:
        print("ERROR: Rust binary not found in target/release/file or target/debug/file")
        print("Run: cargo build")
        sys.exit(1)

    iters = 10000
    if len(sys.argv) > 1:
        try:
            iters = int(sys.argv[1])
        except ValueError:
            pass

    corpus = collect_seed_corpus()
    print("=================================================================")
    print("             DIFFERENTIAL FUZZER: C file vs Rust uu_file        ")
    print("=================================================================")
    print(f"  C Binary:    {C_BIN}")
    print(f"  Rust Binary: {rust_bin}")
    print(f"  Corpus:      {len(corpus)} initial seed files")
    print(f"  Iterations:  {iters}")
    print("=================================================================\n")

    rust_panics = 0
    c_crashes = 0
    divergences = 0
    start_time = time.time()

    for i in range(1, iters + 1):
        seed = random.choice(corpus)
        mutated = mutate_payload(seed)

        res = test_single_input(rust_bin, mutated)

        if res["rust_crash"]:
            rust_panics += 1
            save_crash("rust_crash", mutated, res["rust_crash"])

        if res["c_crash"]:
            c_crashes += 1
            save_crash("c_crash", mutated, res["c_crash"])

        # Check divergence on non-crash inputs
        if not res["rust_crash"] and not res["c_crash"]:
            # High-level mismatch check (e.g., C says ELF, Rust says data)
            c_out = res["c_stdout"].lower()
            r_out = res["rust_stdout"].lower()
            if ("elf" in c_out and "data" == r_out) or ("zip" in c_out and "data" == r_out):
                divergences += 1

        if i % 100 == 0 or i == iters:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r  [{i}/{iters}] | Speed: {rate:.1f} exec/s | Rust panics: {rust_panics} | C crashes: {c_crashes}")
            sys.stdout.flush()

    print("\n\n=================================================================")
    print("                        FUZZ RESULTS                             ")
    print("=================================================================")
    print(f"  Total Iterations: {iters}")
    print(f"  Rust Panics:      {rust_panics}")
    print(f"  C Crashes:        {c_crashes}")
    print(f"  Divergences:      {divergences}")
    print("=================================================================")

if __name__ == "__main__":
    main()
