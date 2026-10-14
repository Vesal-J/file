// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::ffi::OsString;
use std::path::PathBuf;

fn run(args: &[&str]) {
    let mut argv: Vec<OsString> = Vec::with_capacity(args.len() + 1);
    argv.push(OsString::from("file"));
    argv.extend(args.iter().map(OsString::from));
    let _ = uu_file::uumain(argv.into_iter());
}

fn build_fixtures() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("uu_file_bench_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);

    std::fs::write(dir.join("test.txt"), "Hello world text file\n").unwrap();
    std::fs::write(dir.join("test.json"), "{\"status\": \"ok\", \"count\": 100}\n").unwrap();
    std::fs::write(dir.join("test.py"), "#!/usr/bin/env python3\nprint('hello')\n").unwrap();
    std::fs::write(dir.join("empty.bin"), "").unwrap();

    dir
}

fn bench_classification(c: &mut Criterion) {
    let dir = build_fixtures();
    let txt_path = dir.join("test.txt").display().to_string();
    let json_path = dir.join("test.json").display().to_string();
    let py_path = dir.join("test.py").display().to_string();

    c.bench_function("classify_ascii_text", |b| {
        b.iter(|| run(&["-b", black_box(&txt_path)]));
    });

    c.bench_function("classify_json", |b| {
        b.iter(|| run(&["-b", black_box(&json_path)]));
    });

    c.bench_function("classify_python_shebang", |b| {
        b.iter(|| run(&["-b", black_box(&py_path)]));
    });
}

criterion_group!(benches, bench_classification);
criterion_main!(benches);
