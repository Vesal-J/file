#![no_main]

use libfuzzer_sys::fuzz_target;
use uu_file::config::Config;
use uu_file::engine::classify_buffer;
use uu_file::magic::MagicDatabase;

fuzz_target!(|data: &[u8]| {
    let mut config = Config::default();
    config.brief = true;
    let magic_db = MagicDatabase::new();

    // Normal mode
    let _ = classify_buffer(data, &config, &magic_db);

    // Keep going mode (-k)
    config.keep_going = true;
    let _ = classify_buffer(data, &config, &magic_db);

    // Uncompress mode (-z)
    config.uncompress = true;
    let _ = classify_buffer(data, &config, &magic_db);
});
