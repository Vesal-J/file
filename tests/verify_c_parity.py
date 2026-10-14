#!/usr/bin/env python3
"""
System-wide Differential Parity Verifier
Runs both C /usr/bin/file and Rust uu_file against thousands of files on the system,
testing standard mode, brief mode, MIME mode, and flags.
"""

import os
import sys
import glob
import subprocess
from collections import defaultdict

C_BIN = "/usr/bin/file"
RUST_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "../target/release/file"))
if not os.path.exists(RUST_BIN):
    RUST_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "../target/debug/file"))

MODES = [
    ("Default (full)", []),
    ("Brief (-b)", ["-b"]),
    ("MIME Full (-i)", ["-i", "-b"]),
    ("MIME Type (--mime-type)", ["--mime-type", "-b"]),
    ("MIME Encoding (--mime-encoding)", ["--mime-encoding", "-b"]),
    ("Extension (--extension)", ["--extension", "-b"]),
    ("Custom Separator (-F ' -> ')", ["-F", " -> "]),
]

def collect_system_files(limit_per_category=150):
    samples = {}

    # Executables & libraries
    bins = [os.path.join("/usr/bin", f) for f in os.listdir("/usr/bin") if os.path.isfile(os.path.join("/usr/bin", f))]
    samples["Executables (ELF)"] = sorted(bins)[:limit_per_category]

    libs = glob.glob("/usr/lib/**/*.so*", recursive=True)
    samples["Shared Libraries (.so)"] = sorted([f for f in libs if os.path.isfile(f) and not os.path.islink(f)])[:limit_per_category]

    # Source code & headers
    headers = glob.glob("/usr/include/**/*.h", recursive=True)
    samples["C/C++ Headers (.h)"] = sorted(headers)[:limit_per_category]

    # Text & configs
    configs = glob.glob("/etc/**/*", recursive=True)
    samples["Configs & Scripts (/etc)"] = sorted([f for f in configs if os.path.isfile(f) and not os.path.islink(f)])[:limit_per_category]

    # Upstream fixtures
    fixtures = glob.glob(os.path.join(os.path.dirname(__file__), "../../c-file/tests/*.testfile"))
    if fixtures:
        samples["Upstream Test Fixtures"] = sorted(fixtures)

    return samples

def run_cmd(bin_path, args, target_files):
    cmd = [bin_path] + args + target_files
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    return res.returncode, res.stdout.splitlines()

def main():
    if not os.path.exists(RUST_BIN):
        print(f"Error: Rust binary not found at {RUST_BIN}. Please run 'cargo build --release' first.")
        sys.exit(1)

    print("=================================================================")
    print("         SYSTEM-WIDE CLI PARITY AUDITOR: C vs Rust               ")
    print("=================================================================")
    print(f"C Binary:    {C_BIN}")
    print(f"Rust Binary: {RUST_BIN}")

    dataset = collect_system_files()
    total_files = sum(len(v) for v in dataset.values())
    print(f"Dataset:     {total_files} distinct files across {len(dataset)} categories")
    print("=================================================================\n")

    overall_tested = 0
    overall_exact = 0

    for cat_name, files in dataset.items():
        if not files:
            continue
        print(f"\n[Category: {cat_name}] ({len(files)} files)")

        for mode_name, flags in MODES:
            c_code, c_out = run_cmd(C_BIN, flags, files)
            r_code, r_out = run_cmd(RUST_BIN, flags, files)

            exact_matches = 0
            mismatches = []

            for i in range(min(len(c_out), len(r_out))):
                c_line = c_out[i].strip()
                r_line = r_out[i].strip()

                if c_line == r_line:
                    exact_matches += 1
                else:
                    mismatches.append((files[i], c_line, r_line))

            total = len(files)
            pct = (exact_matches / total * 100) if total > 0 else 0
            overall_tested += total
            overall_exact += exact_matches

            status = "PERFECT" if exact_matches == total else f"{pct:.1f}% match"
            print(f"  * {mode_name:<30} -> {exact_matches}/{total} match ({status})")

            # Show first 2 mismatches if any
            if mismatches and len(mismatches) < total:
                for f, c_l, r_l in mismatches[:2]:
                    f_name = os.path.basename(f)
                    print(f"      [diff in {f_name}]")
                    print(f"        C:    \"{c_l}\"")
                    print(f"        Rust: \"{r_l}\"")

    print("\n=================================================================")
    total_pct = (overall_exact / overall_tested * 100) if overall_tested > 0 else 0
    print(f"  TOTAL PARITY SCORE: {overall_exact}/{overall_tested} ({total_pct:.1f}% identical lines)")
    print("=================================================================")

if __name__ == "__main__":
    main()
