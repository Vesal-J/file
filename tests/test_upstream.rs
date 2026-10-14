// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use std::fs;
use std::path::PathBuf;
use uu_file::config::Config;
use uu_file::engine::classify_file;
use uu_file::magic::MagicDatabase;

fn find_tests_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("tests/fixtures"),
        manifest_dir.join("../c-file/tests"),
        manifest_dir.join("c-file/tests"),
    ];

    for c in &candidates {
        if c.is_dir() {
            return Some(c.clone());
        }
    }
    None
}

#[test]
fn test_all_upstream_c_fixtures() {
    let tests_dir = match find_tests_dir() {
        Some(d) => d,
        None => {
            eprintln!("Skipping upstream tests: tests directory not found");
            return;
        }
    };

    let mut entries: Vec<PathBuf> = fs::read_dir(&tests_dir)
        .expect("read tests dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("testfile"))
        .collect();

    entries.sort();

    println!("\n========================================================");
    println!(" RUNNING UPSTREAM astron/file TEST SUITE ({} fixtures)", entries.len());
    println!("========================================================");

    let mut passed = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for testfile in &entries {
        let file_stem = testfile.file_stem().unwrap().to_str().unwrap();
        let result_file = tests_dir.join(format!("{file_stem}.result"));
        let flags_file = tests_dir.join(format!("{file_stem}.flags"));

        if !result_file.is_file() {
            continue;
        }

        let expected_raw = fs::read_to_string(&result_file).unwrap_or_default();
        let expected = expected_raw.trim_end_matches(['\r', '\n']);

        let mut config = Config::default();
        config.brief = true;

        if flags_file.is_file() {
            let flags = fs::read_to_string(&flags_file).unwrap_or_default();
            if flags.contains('k') {
                config.keep_going = true;
            }
        }

        // Check for custom magic files: <stem>*.magic
        let mut magic_db = MagicDatabase::new();
        let mut magic_files: Vec<PathBuf> = Vec::new();
        if let Ok(dir_entries) = fs::read_dir(&tests_dir) {
            for entry in dir_entries.flatten() {
                let p = entry.path();
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with(file_stem) && name.ends_with(".magic") {
                        magic_files.push(p);
                    }
                }
            }
        }
        magic_files.sort();
        for mf in &magic_files {
            let _ = magic_db.load_file(mf);
        }

        match classify_file(testfile, &config, &magic_db) {
            Ok(res) => {
                let actual = res.description.trim();
                if actual == expected {
                    passed += 1;
                    println!("  [PASS] {file_stem}");
                } else {
                    failed += 1;
                    failures.push((
                        file_stem.to_string(),
                        expected.to_string(),
                        actual.to_string(),
                    ));
                    println!("  [FAIL] {file_stem}");
                    println!("         Expected: \"{expected}\"");
                    println!("         Got:      \"{actual}\"");
                }
            }
            Err(e) => {
                failed += 1;
                failures.push((
                    file_stem.to_string(),
                    expected.to_string(),
                    format!("ERROR: {e}"),
                ));
                println!("  [FAIL] {file_stem} (ERROR: {e})");
            }
        }
    }

    let total = passed + failed;
    let pct = if total > 0 {
        (passed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    println!("========================================================");
    println!(" SUMMARY: {passed}/{total} tests passed ({pct:.1}%)");
    println!("========================================================\n");
}
