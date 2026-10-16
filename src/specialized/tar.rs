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

    // Check for Gentoo GLEP 78 binary package: first member starts with <directory>/gpkg-1
    let first_name_bytes = &header[..100];
    let first_name_len = first_name_bytes.iter().position(|&b| b == 0).unwrap_or(first_name_bytes.len());
    if let Ok(first_name) = std::str::from_utf8(&first_name_bytes[..first_name_len]) {
        if let Some(idx) = first_name.find("/gpkg-1") {
            if idx + 7 == first_name.len() {
                let pkg_name = &first_name[..idx];
                let mut comp_str = String::new();
                if buffer.len() >= 1024 {
                    let sec_name_bytes = &buffer[512..612];
                    let sec_len = sec_name_bytes.iter().position(|&b| b == 0).unwrap_or(sec_name_bytes.len());
                    if let Ok(sec_name) = std::str::from_utf8(&sec_name_bytes[..sec_len]) {
                        if let Some(tar_pos) = sec_name.find(".tar.") {
                            let ext = &sec_name[tar_pos + 5..];
                            let c = match ext {
                                "gz" => "using gzip compression",
                                "bz2" => "using bzip2 compression",
                                "lz" => "using lzip compression",
                                "lz4" => "using lz4 compression",
                                "lzo" => "using lzo compression",
                                "xz" => "using xz compression",
                                "zst" => "using zstd compression",
                                _ => "",
                            };
                            if !c.is_empty() {
                                comp_str = format!(" {c}");
                            }
                        }
                    }
                }
                return Some(SpecializedResult {
                    description: format!("Gentoo GLEP 78 (GPKG) binary package for \"{pkg_name}\"{comp_str}"),
                    mime_type: "application/vnd.gentoo.gpkg".to_string(),
                    mime_encoding: "binary".to_string(),
                    extensions: "tar".to_string(),
                    apple: "UNKNUNKN".to_string(),
                });
            }
        }
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
