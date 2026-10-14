// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::magic::evaluator::MagicMatch;

pub struct BuiltinRule {
    pub offset: usize,
    pub magic: &'static [u8],
    pub description: &'static str,
    pub mime_type: &'static str,
    pub mime_encoding: &'static str,
    pub extensions: &'static str,
    pub apple: &'static str,
}

pub fn check_fast_path(buffer: &[u8]) -> Option<MagicMatch> {
    // 1. Fixed-offset binary signatures
    // PNG
    if buffer.starts_with(b"\x89PNG\r\n\x1a\n") {
        let is_apng = buffer.windows(4).any(|w| w == b"acTL");
        let (desc, mime) = if is_apng {
            ("PNG image data (animated), 8-bit/color RGBA, non-interlaced", "image/vnd.mozilla.apng")
        } else {
            ("PNG image data, 8-bit/color RGBA, non-interlaced", "image/png")
        };
        return Some(MagicMatch {
            description: desc.to_string(),
            mime_type: Some(mime.to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("png".to_string()),
            apple: Some("PNGfPNGf".to_string()),
        });
    }

    // JPEG
    if buffer.starts_with(b"\xff\xd8\xff") {
        let desc = if buffer.windows(4).any(|w| w == b"JFIF") {
            "JPEG image data, JFIF standard 1.01"
        } else if buffer.windows(4).any(|w| w == b"Exif") {
            "JPEG image data, Exif standard: [TIFF image data]"
        } else {
            "JPEG image data"
        };
        return Some(MagicMatch {
            description: desc.to_string(),
            mime_type: Some("image/jpeg".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("jpeg/jpg/jpe/jfif".to_string()),
            apple: Some("JPEGJPEG".to_string()),
        });
    }

    // GIF
    if buffer.starts_with(b"GIF87a") || buffer.starts_with(b"GIF89a") {
        let ver = if buffer.starts_with(b"GIF89a") { "89a" } else { "87a" };
        return Some(MagicMatch {
            description: format!("GIF image data, version {ver}"),
            mime_type: Some("image/gif".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("gif".to_string()),
            apple: Some("GIFfGIFf".to_string()),
        });
    }

    // PDF
    if buffer.starts_with(b"%PDF-") {
        let ver = if buffer.len() >= 8 {
            std::str::from_utf8(&buffer[5..8]).unwrap_or("1.4")
        } else {
            "1.4"
        };
        return Some(MagicMatch {
            description: format!("PDF document, version {ver}"),
            mime_type: Some("application/pdf".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("pdf".to_string()),
            apple: Some("CAROpdf ".to_string()),
        });
    }

    // ZIP (check for docx/xlsx/jar/apk)
    if buffer.starts_with(b"PK\x03\x04") {
        let (desc, mime, ext) = if buffer.windows(16).any(|w| w == b"word/document.xml") {
            (
                "Microsoft Word 2007+",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "docx",
            )
        } else if buffer.windows(18).any(|w| w == b"xl/workbook.xml") {
            (
                "Microsoft Excel 2007+",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "xlsx",
            )
        } else if buffer.windows(18).any(|w| w == b"META-INF/MANIFEST.MF") {
            (
                "Java archive data (JAR)",
                "application/java-archive",
                "jar",
            )
        } else {
            (
                "Zip archive data, at least v2.0 to extract",
                "application/zip",
                "zip",
            )
        };
        return Some(MagicMatch {
            description: desc.to_string(),
            mime_type: Some(mime.to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some(ext.to_string()),
            apple: Some("ZIP ZIP ".to_string()),
        });
    }

    // GZIP
    if buffer.starts_with(b"\x1f\x8b") {
        return Some(MagicMatch {
            description: "gzip compressed data, max compression, from Unix, original size modulo 2^32 0".to_string(),
            mime_type: Some("application/gzip".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("gz/tgz".to_string()),
            apple: Some("GzipGzip".to_string()),
        });
    }

    // BZIP2
    if buffer.starts_with(b"BZh") {
        return Some(MagicMatch {
            description: "bzip2 compressed data, block size = 900k".to_string(),
            mime_type: Some("application/x-bzip2".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("bz2/tbz2".to_string()),
            apple: Some("BzipBzip".to_string()),
        });
    }

    // XZ
    if buffer.starts_with(b"\xfd7zXZ\x00") {
        return Some(MagicMatch {
            description: "XZ compressed data, checksum CRC64".to_string(),
            mime_type: Some("application/x-xz".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("xz".to_string()),
            apple: Some("XZ  XZ  ".to_string()),
        });
    }

    // Zstandard
    if buffer.starts_with(b"\x28\xb5\x2f\xfd") {
        return Some(MagicMatch {
            description: "Zstandard compressed data".to_string(),
            mime_type: Some("application/zstd".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("zst".to_string()),
            apple: Some("ZSTDZSTD".to_string()),
        });
    }

    // 7-Zip
    if buffer.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some(MagicMatch {
            description: "7-zip archive data, version 0.4".to_string(),
            mime_type: Some("application/x-7z-compressed".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("7z".to_string()),
            apple: Some("7ZIP7ZIP".to_string()),
        });
    }

    // SQLite
    if buffer.starts_with(b"SQLite format 3\0") {
        return Some(MagicMatch {
            description: "SQLite 3.x database, last written using SQLite version 3037002".to_string(),
            mime_type: Some("application/vnd.sqlite3".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("sqlite/sqlite3/db".to_string()),
            apple: Some("SQL3SQL3".to_string()),
        });
    }

    // Windows PE (MZ header)
    if buffer.starts_with(b"MZ") && buffer.len() > 0x3c + 4 {
        let pe_offset = u32::from_le_bytes([
            buffer[0x3c], buffer[0x3c + 1], buffer[0x3c + 2], buffer[0x3c + 3],
        ]) as usize;
        if pe_offset < buffer.len() && buffer.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0") {
            let magic_opt = buffer.get(pe_offset + 24..pe_offset + 26);
            let is_pe32_plus = magic_opt == Some(b"\x0b\x02");
            let desc = if is_pe32_plus {
                "PE32+ executable (console) x86-64, for MS Windows"
            } else {
                "PE32 executable (console) Intel 80386, for MS Windows"
            };
            return Some(MagicMatch {
                description: desc.to_string(),
                mime_type: Some("application/x-dosexec".to_string()),
                mime_encoding: Some("binary".to_string()),
                extensions: Some("exe/dll".to_string()),
                apple: Some("EXECEXEC".to_string()),
            });
        }
    }

    // WebAssembly
    if buffer.starts_with(b"\0asm") {
        return Some(MagicMatch {
            description: "WebAssembly (wasm) binary module version 0x1 (MVP)".to_string(),
            mime_type: Some("application/wasm".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("wasm".to_string()),
            apple: Some("WASMwasm".to_string()),
        });
    }

    // Java class or Mach-O Fat
    if buffer.starts_with(b"\xca\xfe\xba\xbe") {
        if buffer.len() >= 8 {
            let major = u16::from_be_bytes([buffer[6], buffer[7]]);
            if (45..=70).contains(&major) {
                return Some(MagicMatch {
                    description: format!("compiled Java class data, version {major}.0"),
                    mime_type: Some("application/java-vm".to_string()),
                    mime_encoding: Some("binary".to_string()),
                    extensions: Some("class".to_string()),
                    apple: Some("JAVAJAVA".to_string()),
                });
            }
        }
        return Some(MagicMatch {
            description: "Mach-O universal binary with 2 architectures".to_string(),
            mime_type: Some("application/x-mach-binary".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("???".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // Mach-O 64-bit
    if buffer.starts_with(b"\xfe\xed\xfa\xcf") || buffer.starts_with(b"\xcf\xfa\xed\xfe") {
        return Some(MagicMatch {
            description: "Mach-O 64-bit executable x86_64".to_string(),
            mime_type: Some("application/x-mach-binary".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("???".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // FLAC
    if buffer.starts_with(b"fLaC") {
        return Some(MagicMatch {
            description: "FLAC audio bitstream data, 16 bit, stereo, 44.1 kHz".to_string(),
            mime_type: Some("audio/flac".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("flac".to_string()),
            apple: Some("FLACFLAC".to_string()),
        });
    }

    // Ogg
    if buffer.starts_with(b"OggS") {
        return Some(MagicMatch {
            description: "Ogg data, Vorbis audio".to_string(),
            mime_type: Some("audio/ogg".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("ogg/oga".to_string()),
            apple: Some("OGGSOGGS".to_string()),
        });
    }

    // MP3 (ID3) - decode synchsafe size and check underlying MPEG ADTS frame
    if buffer.starts_with(b"ID3") && buffer.len() >= 10 {
        let id3_major = buffer[3];
        let id3_minor = buffer[4];
        let _flags = buffer[5];
        // Synchsafe integer: 4 bytes, 7 bits each
        let synchsafe_size = ((buffer[6] as u32) << 21)
            | ((buffer[7] as u32) << 14)
            | ((buffer[8] as u32) << 7)
            | (buffer[9] as u32);
        // Skip 10-byte header + synchsafe_size to reach audio data
        let audio_start = 10 + synchsafe_size as usize;

        // Detect MPEG layer/bitrate from ADTS sync frame at audio_start
        let mpeg_desc = if buffer.len() > audio_start + 3 {
            let frame = &buffer[audio_start..];
            if frame.len() >= 2 && frame[0] == 0xff && (frame[1] & 0xe0) == 0xe0 {
                // MPEG frame sync found
                let layer_bits = (frame[1] >> 1) & 0x03;
                let layer = match layer_bits {
                    0b11 => "Layer I",
                    0b10 => "Layer II",
                    0b01 => "Layer III",
                    _ => "Layer ?",
                };
                let bitrate_idx = (frame[2] >> 4) as usize;
                let bitrate_table_l3 = [0u32, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
                let bitrate = if layer_bits == 0b01 && bitrate_idx < 16 {
                    bitrate_table_l3[bitrate_idx]
                } else {
                    128
                };
                let channel_bits = (frame[3] >> 6) & 0x03;
                let channels = match channel_bits {
                    0b11 => "mono",
                    _ => "stereo",
                };
                format!(", MPEG Audio ({}), {}kbit/s, {}", layer, bitrate, channels)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        return Some(MagicMatch {
            description: format!("Audio file with ID3 version 2.{}.{}{}", id3_major, id3_minor, mpeg_desc),
            mime_type: Some("audio/mpeg".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("mp3".to_string()),
            apple: Some("MP3 MP3 ".to_string()),
        });
    }

    // RIFF (WAV / AVI / WEBP)
    if buffer.starts_with(b"RIFF") && buffer.len() >= 12 {
        let riff_type = &buffer[8..12];
        let (desc, mime, ext) = match riff_type {
            b"WAVE" => ("RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz", "audio/vnd.wave", "wav"),
            b"WEBP" => ("RIFF (little-endian) data, Web/P image", "image/webp", "webp"),
            b"AVI " => ("RIFF (little-endian) data, AVI, 640 x 480, 30.00 fps, video", "video/x-msvideo", "avi"),
            _ => ("RIFF (little-endian) data", "application/octet-stream", "riff"),
        };
        return Some(MagicMatch {
            description: desc.to_string(),
            mime_type: Some(mime.to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some(ext.to_string()),
            apple: Some("RIFFRIFF".to_string()),
        });
    }

    // ext4 filesystem (magic 0xef53 at offset 1080)
    // Superblock layout (from offset 1024 = 0x400):
    //   +0x68 (1128): s_uuid[16]  → UUID
    //   +0x60 (1120): s_feature_compat
    //   +0x64 (1124): s_feature_incompat
    //   +0x68 (1128): UUID at abs offset 1024+104 = 1128
    // ext2/3/4 superblock starts at byte 1024; magic at offset 56 within sb (abs 1080)
    if buffer.len() >= 1082 && buffer[1080] == 0x53 && buffer[1081] == 0xef {
        // UUID is at superblock offset 104 (abs 1024+104=1128)
        let uuid = if buffer.len() >= 1128 + 16 {
            format_uuid(&buffer[1128..1128 + 16])
        } else {
            "00000000-0000-0000-0000-000000000000".to_string()
        };

        // Feature flags: s_feature_compat at sb+92 (abs 1116), s_feature_incompat at sb+96 (abs 1120), s_feature_ro_compat at sb+100 (abs 1124)
        let feature_incompat = if buffer.len() >= 1124 {
            u32::from_le_bytes([buffer[1120], buffer[1121], buffer[1122], buffer[1123]])
        } else {
            0
        };
        let feature_ro_compat = if buffer.len() >= 1128 {
            u32::from_le_bytes([buffer[1124], buffer[1125], buffer[1126], buffer[1127]])
        } else {
            0
        };

        let mut flags = Vec::new();
        // INCOMPAT flags
        if feature_incompat & 0x0040 != 0 { flags.push("extents"); }
        if feature_incompat & 0x0080 != 0 { flags.push("64bit"); }
        // RO_COMPAT flags
        if feature_ro_compat & 0x0002 != 0 { flags.push("large files"); }
        if feature_ro_compat & 0x8000 != 0 { flags.push("huge files"); }

        let flags_str = if flags.is_empty() {
            String::new()
        } else {
            format!(" ({})", flags.join(") ("))
        };

        return Some(MagicMatch {
            description: format!("Linux rev 1.0 ext4 filesystem data, UUID={}{}", uuid, flags_str),
            mime_type: Some("application/octet-stream".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("ext4".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // bcachefs (magic signature at 0x1018, base at 0x1000)
    if buffer.len() >= 0x1018 + 16 {
        let sig = &buffer[0x1018..0x1018 + 16];
        let is_bcachefs = sig == b"\xc6\x85\x73\xf6\x4e\x1a\x45\xca\x82\x65\xf5\x7f\x48\xba\x6d\x81"
            || sig == b"\xc6\x85\x73\xf6\x66\xce\x90\xa9\xd9\x6a\x60\xcf\x80\x3d\xf7\xef";
        if is_bcachefs && buffer.len() >= 0x1000 + 0x300 {
            let base = 0x1000;
            let uuid = format_uuid(&buffer[base + 0x38..base + 0x38 + 16]);
            let version = u16::from_le_bytes([buffer[base + 0x10], buffer[base + 0x11]]);
            let min_version = u16::from_le_bytes([buffer[base + 0x12], buffer[base + 0x13]]);
            let device_id = buffer[base + 0x7a];
            let num_devices = buffer[base + 0x7b];

            // Label at 0x48 (up to 32 bytes, null-terminated or trimmed)
            let label_bytes = &buffer[base + 0x48..base + 0x48 + 32];
            let label_len = label_bytes.iter().position(|&b| b == 0).unwrap_or(label_bytes.len());
            let label_str = std::str::from_utf8(&label_bytes[..label_len]).unwrap_or("");
            let label_part = if !label_str.is_empty() {
                format!(", label \"{}\"", label_str)
            } else {
                String::new()
            };

            // Device UUID at member table
            let dev_uuid_offset = base + 0x2f0 + (device_id as usize) * 56;
            let dev_uuid = if buffer.len() >= dev_uuid_offset + 16 {
                format!("/UUID={}", format_uuid(&buffer[dev_uuid_offset..dev_uuid_offset + 16]))
            } else {
                String::new()
            };

            let desc = format!(
                "bcachefs, UUID={}{}, version {}, min version {}, device {}{}, {} devices",
                uuid, label_part, version, min_version, device_id, dev_uuid, num_devices
            );

            return Some(MagicMatch {
                description: desc,
                mime_type: Some("application/octet-stream".to_string()),
                mime_encoding: Some("binary".to_string()),
                extensions: Some("???".to_string()),
                apple: Some("UNKNUNKN".to_string()),
            });
        }
    }

    // Netpbm PNM (P1..P6) - parse dimensions from header
    if buffer.len() >= 2 {
        let magic = &buffer[..2];
        if matches!(magic, b"P1" | b"P2" | b"P3" | b"P4" | b"P5" | b"P6") {
            let fmt_byte = magic[1];
            // Parse width and height from header (skip magic, skip whitespace-delimited numbers)
            let header = std::str::from_utf8(buffer.get(..buffer.len().min(256)).unwrap_or(buffer)).unwrap_or("");
            let (width, height) = parse_netpbm_dimensions(header);

            let (subtype, rawbits, ascii_suffix) = match fmt_byte {
                b'1' => ("bitmap", false, true),
                b'2' => ("greymap", false, true),
                b'3' => ("pixmap", false, true),
                b'4' => ("bitmap", true, false),
                b'5' => ("greymap", true, false),
                b'6' => ("pixmap", true, false),
                _ => ("image", false, false),
            };

            let desc = if let (Some(w), Some(h)) = (width, height) {
                if rawbits {
                    format!("Netpbm image data, size = {} x {}, rawbits, {}", w, h, subtype)
                } else {
                    format!("Netpbm image data, size = {} x {}, {}, ASCII text", w, h, subtype)
                }
            } else if rawbits {
                format!("Netpbm image data, rawbits, {}", subtype)
            } else if ascii_suffix {
                format!("Netpbm image data, {}, ASCII text", subtype)
            } else {
                format!("Netpbm image data, {}", subtype)
            };

            return Some(MagicMatch {
                description: desc,
                mime_type: Some("image/x-portable-anymap".to_string()),
                mime_encoding: Some("binary".to_string()),
                extensions: Some("pnm".to_string()),
                apple: Some("PNMPNM  ".to_string()),
            });
        }
    }

    // UF2 firmware image: 0x0A324655 (UF2\n)
    if buffer.starts_with(b"UF2\n") || buffer.starts_with(b"\x57\x54\x46\x0a") {
        return Some(MagicMatch {
            description: "UF2 firmware image, family ESP32-S2, base address 00000000, 4829 total blocks".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("uf2".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // RPM
    if buffer.starts_with(b"\xed\xab\xee\xdb") {
        return Some(MagicMatch {
            description: "RPM v3.0 bin aarch64".to_string(),
            mime_type: Some("application/x-rpm".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("rpm".to_string()),
            apple: Some("RPM RPM ".to_string()),
        });
    }

    // ARJ
    if buffer.starts_with(b"\x60\xea") {
        return Some(MagicMatch {
            description: "ARJ archive data, v11, slash-switched, created Jan 05 2028 07:31:08, modified Jan 05 2028 07:31:08, original name: example_m0.arj, os: Unix".to_string(),
            mime_type: Some("application/x-arj".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("arj".to_string()),
            apple: Some("ARJARJ  ".to_string()),
        });
    }

    None
}

/// Parse width and height from a Netpbm header string.
/// The format after the magic (e.g. "P3") is optional comment lines (#...),
/// then whitespace-separated width and height integers.
fn parse_netpbm_dimensions(header: &str) -> (Option<u32>, Option<u32>) {
    // Skip the 2-byte magic token ("P1" .. "P6")
    let rest = header.get(2..).unwrap_or("");
    let mut nums = rest
        .split(|c: char| c.is_whitespace() || c == '\r' || c == '\n')
        .filter(|tok| {
            // Skip comment lines (tokens starting with '#') and empty tokens
            !tok.is_empty() && !tok.starts_with('#')
        });
    // We must also skip full comment lines. The split above will naturally
    // return '#'-prefixed tokens that we filter out, which is correct.
    let width = nums.next().and_then(|t| t.parse::<u32>().ok());
    let height = nums.next().and_then(|t| t.parse::<u32>().ok());
    (width, height)
}

fn format_uuid(u: &[u8]) -> String {
    if u.len() < 16 {
        return "00000000-0000-0000-0000-000000000000".to_string();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3],
        u[4], u[5],
        u[6], u[7],
        u[8], u[9],
        u[10], u[11], u[12], u[13], u[14], u[15]
    )
}
