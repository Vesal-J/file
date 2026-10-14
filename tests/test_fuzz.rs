// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use std::fs;
use std::path::PathBuf;
use uu_file::config::Config;
use uu_file::engine::classify_buffer;
use uu_file::magic::parser::parse_magic_file;
use uu_file::magic::MagicDatabase;
use uu_file::specialized;

/// Minimal deterministic PRNG (SplitMix64) for reproducible in-tree fuzzing without external crates.
struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        if upper == 0 {
            0
        } else {
            (self.next_u64() as usize) % upper
        }
    }

    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    fn next_byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// Mutator that performs Havoc-style mutations on input byte buffers.
struct BufferMutator {
    rng: FuzzRng,
    dictionary: Vec<Vec<u8>>,
}

impl BufferMutator {
    fn new(seed: u64) -> Self {
        let dictionary = vec![
            b"\x7fELF".to_vec(),
            b"PK\x03\x04".to_vec(),
            b"\x1f\x8b".to_vec(),
            b"BZh9".to_vec(),
            b"\xfd7zXZ\x00".to_vec(),
            b"7z\xbc\xaf\x27\x1c".to_vec(),
            b"\x28\xb5\x2f\xfd".to_vec(),
            b"GIF89a".to_vec(),
            b"\x89PNG\r\n\x1a\n".to_vec(),
            b"\xff\xd8\xff".to_vec(),
            b"%PDF-1.7".to_vec(),
            b"SQLite format 3\0".to_vec(),
            b"{\x22key\x22: [".to_vec(),
            b"ustar\00000".to_vec(),
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec(), // CDF header
            b"\xc6\x85\x73\xf6\x4e\x1a\x45\xca\x82\x65\xf5\x7f\x48\xba\x6d\x81".to_vec(), // bcachefs
            b"\xef\x53".to_vec(), // ext4 magic
            b"ID3\x04\x00\x00\x00\x00\x02\x00".to_vec(), // MP3 ID3v2.4
            b"fLaC".to_vec(),
            b"OggS".to_vec(),
            b"RIFF\x24\x00\x00\x00WAVE".to_vec(),
            b"UF2\n".to_vec(),
            b"#! /bin/sh\n".to_vec(),
            b"%s%s%s%s%s%n%n".to_vec(), // format string bomb
            b"\0\0\0\0".to_vec(),
            b"\xff\xff\xff\xff".to_vec(),
        ];
        Self {
            rng: FuzzRng::new(seed),
            dictionary,
        }
    }

    fn mutate(&mut self, buf: &mut Vec<u8>) {
        if buf.is_empty() {
            let dict_idx = self.rng.next_usize(self.dictionary.len());
            buf.extend_from_slice(&self.dictionary[dict_idx]);
            return;
        }

        let num_mutations = self.rng.next_usize(3) + 1;
        for _ in 0..num_mutations {
            if buf.is_empty() {
                let dict_idx = self.rng.next_usize(self.dictionary.len());
                buf.extend_from_slice(&self.dictionary[dict_idx]);
                continue;
            }

            let op = self.rng.next_usize(9);
            match op {
                0 => {
                    // Bit flip
                    let idx = self.rng.next_usize(buf.len());
                    let bit = 1 << self.rng.next_usize(8);
                    buf[idx] ^= bit;
                }
                1 => {
                    // Interesting byte replacement
                    let idx = self.rng.next_usize(buf.len());
                    let interesting = [0x00, 0x01, 0x7f, 0x80, 0xff, b'\\', b'/', b'%', b'\n', b'\0', b'"', b':'];
                    buf[idx] = interesting[self.rng.next_usize(interesting.len())];
                }
                2 => {
                    // Random byte overwrite
                    let idx = self.rng.next_usize(buf.len());
                    buf[idx] = self.rng.next_byte();
                }
                3 => {
                    // Delete byte(s)
                    if buf.len() > 1 {
                        let idx = self.rng.next_usize(buf.len());
                        buf.remove(idx);
                    }
                }
                4 => {
                    // Insert random byte
                    if buf.len() < 65536 {
                        let idx = self.rng.next_usize(buf.len() + 1);
                        buf.insert(idx, self.rng.next_byte());
                    }
                }
                5 => {
                    // Insert dictionary token
                    if buf.len() < 65536 {
                        let dict_idx = self.rng.next_usize(self.dictionary.len());
                        let token = &self.dictionary[dict_idx];
                        let idx = self.rng.next_usize(buf.len() + 1);
                        buf.splice(idx..idx, token.iter().cloned());
                    }
                }
                6 => {
                    // Truncate
                    if buf.len() > 1 {
                        let new_len = self.rng.next_usize(buf.len());
                        buf.truncate(new_len);
                    }
                }
                7 => {
                    // Swap two adjacent bytes
                    if buf.len() >= 2 {
                        let idx = self.rng.next_usize(buf.len() - 1);
                        buf.swap(idx, idx + 1);
                    }
                }
                8 => {
                    // Insert boundary integers (u16, u32, u64 edge cases)
                    if buf.len() < 65536 {
                        let boundaries: &[u64] = &[0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0xffff, 0x7fffffff, 0xffffffff, u64::MAX];
                        let val = boundaries[self.rng.next_usize(boundaries.len())];
                        let bytes = if self.rng.next_bool() {
                            val.to_le_bytes()
                        } else {
                            val.to_be_bytes()
                        };
                        let idx = self.rng.next_usize(buf.len() + 1);
                        buf.splice(idx..idx, bytes.iter().cloned());
                    }
                }
                _ => {}
            }
        }
    }
}

fn load_initial_seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();

    // 1. Synthetic edge-case seeds
    seeds.push(Vec::new()); // Empty buffer
    seeds.push(vec![0]);    // Single null byte
    seeds.push(vec![0xff]); // Single 0xFF
    seeds.push(vec![0; 256]); // All zeros
    seeds.push(vec![0xff; 256]); // All ones
    seeds.push(b"Hello World\n".to_vec());
    seeds.push(b"{\x22name\x22: \x22test\x22, \x22values\x22: [1, 2, 3]}\n".to_vec());
    seeds.push(b"a,b,c\n1,2,3\n4,5,6\n".to_vec());
    seeds.push(b"\x7fELF\x02\x01\x01\x00\0\0\0\0\0\0\0\0\x02\x00\x3e\x00\x01\x00\0\0".to_vec());
    seeds.push(b"P3\n# comment\n2 2\n255\n255 0 0 0 255 0 0 0 255 255 255 255\n".to_vec());

    // 2. Load upstream test fixtures if available
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("../c-file/tests"),
        manifest_dir.join("c-file/tests"),
        manifest_dir.join("tests/fixtures"),
    ];

    for c in &candidates {
        if c.is_dir() {
            if let Ok(entries) = fs::read_dir(c) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|s| s.to_str()) == Some("testfile") {
                        if let Ok(bytes) = fs::read(&p) {
                            seeds.push(bytes);
                        }
                    }
                }
            }
            break;
        }
    }

    seeds
}

#[test]
fn test_fuzz_classification_engine() {
    let seeds = load_initial_seeds();
    assert!(!seeds.is_empty(), "Seeds must not be empty");

    let iters = std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2_000);

    println!("\n[FUZZ] Running {iters} iterations on classification engine...");

    let mut mutator = BufferMutator::new(0xdeadbeef1337);
    let magic_db = MagicDatabase::new();

    let mut normal_config = Config::default();
    normal_config.brief = true;

    let mut keep_going_config = Config::default();
    keep_going_config.brief = true;
    keep_going_config.keep_going = true;

    let mut uncompress_config = Config::default();
    uncompress_config.brief = true;
    uncompress_config.uncompress = true;

    for i in 0..iters {
        let seed_idx = mutator.rng.next_usize(seeds.len());
        let mut sample = seeds[seed_idx].clone();

        mutator.mutate(&mut sample);

        // 1. Normal classification
        let res_normal = classify_buffer(&sample, &normal_config, &magic_db);
        assert!(res_normal.is_ok(), "classify_buffer should never return Err on memory buffer (iter {i})");
        let r = res_normal.unwrap();
        assert!(!r.description.is_empty(), "description must not be empty (iter {i})");

        // 2. Keep-going mode (-k)
        let res_kg = classify_buffer(&sample, &keep_going_config, &magic_db);
        assert!(res_kg.is_ok(), "classify_buffer keep_going must not error (iter {i})");

        // 3. Decompression mode (-z)
        let res_z = classify_buffer(&sample, &uncompress_config, &magic_db);
        assert!(res_z.is_ok(), "classify_buffer uncompress must not error (iter {i})");
    }

    println!("[FUZZ] Classification engine passed {iters} fuzz iterations without panics!");
}

#[test]
fn test_fuzz_magic_parser() {
    let iters = std::env::var("FUZZ_MAGIC_ITERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1_000);

    println!("\n[FUZZ] Running {iters} iterations on magic rule parser...");

    let mut mutator = BufferMutator::new(0x42424242cafe);

    let base_magic_rules = [
        "0 string \\x7fELF ELF executable\n>4 byte 1 32-bit\n>4 byte 2 64-bit\n",
        "0 search/8192 PK\\x03\\x04 Zip archive\n!:mime application/zip\n",
        "0 leshort 0xef53 ext4 filesystem\n>104 guid x UUID=%s\n",
        "0 regex/1024 ^[A-Za-z0-9_-]+$ Token identifier\n",
        "0 (0x3c.l) string PE\\0\\0 Portable Executable\n",
        "0 clear\n0 default Data file\n",
    ];

    for i in 0..iters {
        let base_idx = mutator.rng.next_usize(base_magic_rules.len());
        let mut sample = base_magic_rules[base_idx].as_bytes().to_vec();

        mutator.mutate(&mut sample);

        // Convert to string (lossy to test unicode boundaries)
        let magic_text = String::from_utf8_lossy(&sample);

        // Parser must never panic, hang, or overflow stack
        let rules = parse_magic_file(&magic_text);

        // Strength calculation must never overflow or panic
        for rule in &rules {
            let _ = rule.strength();
            for child in &rule.children {
                let _ = child.strength();
            }
        }
    }

    println!("[FUZZ] Magic parser passed {iters} fuzz iterations without panics!");
}

#[test]
fn test_fuzz_specialized_parsers() {
    let iters = std::env::var("FUZZ_SPECIAL_ITERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2_000);

    println!("\n[FUZZ] Running {iters} iterations directly on specialized parsers...");

    let mut mutator = BufferMutator::new(0xabcdef0123456789);
    let config = Config::default();

    // Targets: ELF, JSON, TAR, CSV, CDF
    for _ in 0..iters {
        let len = mutator.rng.next_usize(4096);
        let mut sample = vec![0u8; len];
        for b in &mut sample {
            *b = mutator.rng.next_byte();
        }
        mutator.mutate(&mut sample);

        // Must safely return Option without crashing on any input slice
        let _ = specialized::test_elf(&sample, &config);
        let _ = specialized::test_json(&sample);
        let _ = specialized::test_tar(&sample);
        let _ = specialized::test_csv(&sample);
        let _ = specialized::test_cdf(&sample);
    }

    println!("[FUZZ] Specialized parsers passed {iters} fuzz iterations!");
}

#[test]
fn test_cve_regressions() {
    println!("\n[FUZZ] Testing historical CVE and DoS edge cases...");

    let config = Config::default();
    let mut magic_db = MagicDatabase::new();

    // 1. CVE-2014-1943: Indirect recursion bomb (self-referencing indirect offset: 0 (0.l) string ...)
    let indirect_bomb = "0 (0.l) string AAAAA Recursive bomb\n";
    let rules = parse_magic_file(indirect_bomb);
    magic_db.custom_rules = rules;

    let zero_payload = vec![0u8; 1024];
    let res = classify_buffer(&zero_payload, &config, &magic_db);
    assert!(res.is_ok(), "Engine must survive indirect recursion bomb without stack overflow");

    // 2. High-depth tree nesting DoS
    let mut deep_nesting = String::new();
    for depth in 0..100 {
        deep_nesting.push_str(&">".repeat(depth));
        deep_nesting.push_str("0 byte 0 nested\n");
    }
    let deep_rules = parse_magic_file(&deep_nesting);
    assert!(deep_rules.len() <= 100);

    // 3. Huge search window with short pattern
    let huge_search = "0 search/65536 needle Found needle\n";
    let search_rules = parse_magic_file(huge_search);
    magic_db.custom_rules = search_rules;
    let hay = vec![b'a'; 32768];
    let res = classify_buffer(&hay, &config, &magic_db);
    assert!(res.is_ok());

    println!("[FUZZ] All CVE regression checks passed cleanly!");
}
