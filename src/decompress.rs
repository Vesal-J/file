// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use std::io::Read;

pub struct DecompressedHolder {
    pub data: Vec<u8>,
    pub compression_type: &'static str,
}

const MAX_DECOMPRESSED_BYTES: usize = 1024 * 1024; // 1 MiB cap to prevent zip-bombs

/// Try to decompress the buffer if a supported compression format is detected.
/// Returns (slice_to_inspect, Option<DecompressedHolder>).
pub fn try_decompress(buffer: &[u8]) -> (Vec<u8>, Option<&'static str>) {
    // 1. Gzip: 1F 8B
    if buffer.starts_with(b"\x1f\x8b") {
        let mut decoder = flate2::read::GzDecoder::new(buffer);
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        while out.len() < MAX_DECOMPRESSED_BYTES {
            match decoder.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let to_take = n.min(MAX_DECOMPRESSED_BYTES - out.len());
                    out.extend_from_slice(&chunk[..to_take]);
                }
                Err(_) => break,
            }
        }
        if !out.is_empty() {
            return (out, Some("gzip compressed data"));
        }
    }

    (Vec::new(), None)
}
