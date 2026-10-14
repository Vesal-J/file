// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::specialized::elf::SpecializedResult;

pub fn test_tar(buffer: &[u8]) -> Option<SpecializedResult> {
    if buffer.len() < 512 {
        return None;
    }

    let header = &buffer[..512];

    // Checksum is located at bytes 148..156
    let chksum_slice = &header[148..156];
    let chksum_str = std::str::from_utf8(chksum_slice).ok()?.trim().trim_matches('\0');
    let expected_chksum = usize::from_str_radix(chksum_str, 8).ok()?;

    // Compute unsigned checksum with chksum bytes treated as spaces (0x20)
    let mut unsigned_sum: usize = 0;
    let mut signed_sum: isize = 0;

    for (i, &b) in header.iter().enumerate() {
        let val = if (148..156).contains(&i) { 0x20 } else { b };
        unsigned_sum += val as usize;
        signed_sum += (val as i8) as isize;
    }

    if unsigned_sum != expected_chksum && (signed_sum as usize) != expected_chksum {
        return None;
    }

    // Check magic at offset 257
    let magic = &header[257..265];
    let desc = if magic.starts_with(b"ustar\x00") {
        "POSIX tar archive"
    } else if magic.starts_with(b"ustar  \x00") || magic.starts_with(b"ustar ") {
        "POSIX tar archive (GNU)"
    } else {
        "tar archive"
    };

    Some(SpecializedResult {
        description: desc.to_string(),
        mime_type: "application/x-tar".to_string(),
        mime_encoding: "binary".to_string(),
        extensions: "tar".to_string(),
        apple: "TAR TAR ".to_string(),
    })
}
