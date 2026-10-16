#!/usr/bin/env python3
import os
import glob
import subprocess

C_BIN = "/usr/bin/file"
RUST_BIN = "/home/vesal/Desktop/rust/file/target/release/file"
fixtures = sorted(glob.glob("/home/vesal/Desktop/rust/c-file/tests/*.testfile"))

for mode_name, flags in [
    ("Default (full)", []),
    ("Brief (-b)", ["-b"]),
    ("MIME Full (-i)", ["-i", "-b"]),
    ("MIME Type (--mime-type)", ["--mime-type", "-b"]),
    ("MIME Encoding (--mime-encoding)", ["--mime-encoding", "-b"]),
    ("Extension (--extension)", ["--extension", "-b"]),
    ("Custom Separator (-F ' -> ')", ["-F", " -> "]),
]:
    c_res = subprocess.run([C_BIN] + flags + fixtures, capture_output=True, text=True).stdout.splitlines()
    r_res = subprocess.run([RUST_BIN] + flags + fixtures, capture_output=True, text=True).stdout.splitlines()
    diffs = []
    for f, c, r in zip(fixtures, c_res, r_res):
        if c.strip() != r.strip():
            diffs.append((os.path.basename(f), c.strip(), r.strip()))
    print(f"=== Mode: {mode_name} ({len(fixtures) - len(diffs)}/{len(fixtures)} match) ===")
    for name, c, r in diffs:
        print(f"  [{name}]\n    C:    {c}\n    Rust: {r}")
