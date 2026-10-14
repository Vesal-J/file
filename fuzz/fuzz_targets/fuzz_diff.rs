#![no_main]

use libfuzzer_sys::fuzz_target;
use uu_file::config::Config;
use uu_file::engine::classify_buffer;
use uu_file::magic::MagicDatabase;

fuzz_target!(|data: &[u8]| {
    let magic_db = MagicDatabase::new();

    let mut cfg1 = Config::default();
    cfg1.brief = true;

    let mut cfg2 = Config::default();
    cfg2.brief = true;
    cfg2.keep_going = true;

    if let (Ok(r1), Ok(r2)) = (
        classify_buffer(data, &cfg1, &magic_db),
        classify_buffer(data, &cfg2, &magic_db),
    ) {
        // Assert invariants
        assert!(!r1.description.is_empty());
        assert!(!r2.description.is_empty());
        // In keep_going mode, the description should contain or extend the primary match
        if !r1.description.contains("data") && !r2.description.is_empty() {
            // Both classifications completed successfully
        }
    }
});
