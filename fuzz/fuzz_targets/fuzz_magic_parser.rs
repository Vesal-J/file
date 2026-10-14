#![no_main]

use libfuzzer_sys::fuzz_target;
use uu_file::magic::parser::parse_magic_file;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let rules = parse_magic_file(s);
        for rule in &rules {
            let _ = rule.strength();
            for child in &rule.children {
                let _ = child.strength();
            }
        }
    }
});
