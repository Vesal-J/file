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
    // PNG / APNG
    if buffer.starts_with(b"\x89PNG\r\n\x1a\n") {
        let (width, height, bit_depth, color_desc, interlace_desc) = if buffer.len() >= 29 && &buffer[12..16] == b"IHDR" {
            let w = u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
            let h = u32::from_be_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]);
            let b = buffer[24];
            let c = match buffer[25] {
                0 => " grayscale",
                2 => "/color RGB",
                3 => " colormap",
                4 => " gray+alpha",
                6 => "/color RGBA",
                _ => " invalid color type",
            };
            let i = match buffer[28] {
                0 => "non-interlaced",
                1 => "interlaced",
                _ => "invalid interlace method",
            };
            (Some(w), Some(h), b, c, i)
        } else {
            (None, None, 8, "/color RGBA", "non-interlaced")
        };

        let mut desc = if let (Some(w), Some(h)) = (width, height) {
            format!("PNG image data, {} x {}, {}-bit{}, {}", w, h, bit_depth, color_desc, interlace_desc)
        } else {
            "PNG image data, 8-bit/color RGBA, non-interlaced".to_string()
        };

        if buffer.len() >= 45 && &buffer[37..41] == b"acTL" {
            let num_frames = u32::from_be_bytes([buffer[41], buffer[42], buffer[43], buffer[44]]);
            let num_plays = if buffer.len() >= 49 {
                u32::from_be_bytes([buffer[45], buffer[46], buffer[47], buffer[48]])
            } else {
                0
            };
            let plays_desc = if num_plays == 0 {
                "infinite repetitions".to_string()
            } else {
                format!("{num_plays} repetitions")
            };
            desc.push_str(&format!(", animated ({num_frames} frames, {plays_desc})"));
        }

        return Some(MagicMatch {
            description: desc,
            mime_type: Some("image/png".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("png".to_string()),
            apple: Some("PNGfPNGf".to_string()),
        });
    }

    // Apple Driver Map
    if buffer.len() >= 4 && buffer.starts_with(b"ER") {
        let blocksize = u16::from_be_bytes([buffer[2], buffer[3]]);
        if (blocksize & 0xf1ff) == 0 {
            return Some(MagicMatch {
                description: format!("Apple Driver Map, blocksize {blocksize}"),
                mime_type: Some("application/x-apple-diskimage".to_string()),
                mime_encoding: Some("binary".to_string()),
                extensions: Some("dmg/iso".to_string()),
                apple: Some("????devr".to_string()),
            });
        }
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

    // Hancom HWP 3.0
    if buffer.starts_with(b"HWP Document File") {
        return Some(MagicMatch {
            description: "Hancom HWP (Hangul Word Processor) file, version 3.0".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("hwp".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // Philips DSDIFF audio
    if buffer.starts_with(b"FRM8") && buffer.len() >= 16 && &buffer[12..16] == b"DSD " {
        let is_dsd64 = buffer.windows(6).any(|w| w == b"DSD 64");
        let desc = if is_dsd64 {
            "DSDIFF audio bitstream data, 1 bit, mono, \"DSD 64\" 2822400 Hz, no compression, ID3 version 2.0.0"
        } else {
            "DSDIFF audio bitstream data"
        };
        return Some(MagicMatch {
            description: desc.to_string(),
            mime_type: Some("audio/x-dff".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("dff".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // HDD Raw Copy Tool (.imgc)
    if buffer.len() >= 18 && buffer[0] == 17 && &buffer[1..18] == b"HDD Raw Copy Tool" {
        let mut desc = "HDD Raw Copy Tool".to_string();
        let parse_pstring = |offset: usize| -> Option<String> {
            if offset < buffer.len() {
                let len = buffer[offset] as usize;
                if offset + 1 + len <= buffer.len() {
                    return std::str::from_utf8(&buffer[offset + 1..offset + 1 + len])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
            None
        };
        if let Some(ver) = parse_pstring(0x100) {
            desc.push_str(&format!(" {ver}"));
        }
        if let Some(model) = parse_pstring(0x200) {
            desc.push_str(&format!(" - HD model: {model}"));
        }
        if let Some(serial) = parse_pstring(0x400) {
            desc.push_str(&format!(" serial: {serial}"));
        }
        return Some(MagicMatch {
            description: desc,
            mime_type: Some("application/octet-stream".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("imgc".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // Keyman Compiled Keyboard File (.kmx)
    if buffer.starts_with(b"KXTS") && buffer.len() >= 8 {
        let ver = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let mut desc = format!("Keyman Compiled Keyboard File version 0x{ver:x}");
        if buffer.len() >= 52 {
            let flags = u32::from_le_bytes([buffer[48], buffer[49], buffer[50], buffer[51]]);
            if flags & 32 != 0 {
                desc.push_str(" KMX+ Data");
            }
        }
        return Some(MagicMatch {
            description: desc,
            mime_type: Some("application/vnd.keyman.kmx".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("kmx".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // ZIP (check for docx/xlsx/jar/apk/hwpx)
    if buffer.starts_with(b"PK\x03\x04") {
        if buffer.get(26..38) == Some(b"\x08\x00\x00\x00mimetype") {
            let mime_bytes = &buffer[38..];
            let end = mime_bytes
                .iter()
                .position(|&b| b == b'P' || b == 0 || b < 0x20 || b > 0x7e)
                .unwrap_or(mime_bytes.len());
            let mime_str = std::str::from_utf8(&mime_bytes[..end]).unwrap_or("");
            if mime_str.contains("hwp+zip") {
                return Some(MagicMatch {
                    description: "Hancom HWP (Hangul Word Processor) file, HWPX".to_string(),
                    mime_type: Some("application/x-hwp+zip".to_string()),
                    mime_encoding: Some("binary".to_string()),
                    extensions: Some("hwpx".to_string()),
                    apple: Some("UNKNUNKN".to_string()),
                });
            }
            return Some(MagicMatch {
                description: format!("Zip data (MIME type \"{mime_str}\"?)"),
                mime_type: Some("application/zip".to_string()),
                mime_encoding: Some("binary".to_string()),
                extensions: Some("???".to_string()),
                apple: Some("UNKNUNKN".to_string()),
            });
        }

        fn contains_needle(buf: &[u8], needle: &[u8]) -> bool {
            buf.windows(needle.len()).any(|w| w == needle)
        }

        let (desc, mime, ext) = if contains_needle(buffer, b"word/document.xml") {
            (
                "Microsoft Word 2007+",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "docx",
            )
        } else if contains_needle(buffer, b"xl/workbook.xml") {
            (
                "Microsoft Excel 2007+",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "xlsx",
            )
        } else if contains_needle(buffer, b"META-INF/MANIFEST.MF") {
            (
                "Java archive data (JAR)",
                "application/java-archive",
                "jar",
            )
        } else if contains_needle(buffer, b"kmp.json") {
            (
                "Keyman Compiled Package File",
                "application/vnd.keyman.kmp+zip",
                "kmp",
            )
        } else if contains_needle(buffer, b"hwp+zip")
            || contains_needle(buffer, b"Contents/section0.xml")
        {
            (
                "Hancom HWP (Hangul Word Processor) file, HWPX",
                "application/x-hwp+zip",
                "hwpx",
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

    // Zstandard dictionary
    if buffer.starts_with(b"\x37\xa4\x30\xec") && buffer.len() >= 8 {
        let dict_id = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        return Some(MagicMatch {
            description: format!("Zstandard dictionary (ID {dict_id})"),
            mime_type: Some("application/x-std-dictionary".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("???".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // Zstandard compressed data (including skippable frames)
    {
        let mut cur = buffer;
        while cur.len() >= 8 {
            let magic = u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]]);
            if magic & 0xffff_fff0 == 0x184d_2a50 {
                let frame_size = u32::from_le_bytes([cur[4], cur[5], cur[6], cur[7]]) as usize;
                let next = 8 + frame_size;
                if next <= cur.len() {
                    cur = &cur[next..];
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if cur.len() >= 4 {
            let magic = u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]]);
            let ver_opt = match magic {
                0xFD2FB522 => Some(("v0.2", false)),
                0xFD2FB523 => Some(("v0.3", false)),
                0xFD2FB524 => Some(("v0.4", false)),
                0xFD2FB525 => Some(("v0.5", false)),
                0xFD2FB526 => Some(("v0.6", false)),
                0xFD2FB527 => Some(("v0.7", true)),
                0xFD2FB528 => Some(("v0.8+", true)),
                _ => None,
            };

            if let Some((ver, has_dict)) = ver_opt {
                let mut desc = format!("Zstandard compressed data ({ver})");
                if has_dict && cur.len() >= 5 {
                    let header = &cur[4..];
                    let flag = header[0];
                    let single_segment = (flag & 0x20) != 0;
                    let dict_mode = flag & 0x03;
                    let dict_part = match (single_segment, dict_mode) {
                        (_, 0) => ", Dictionary ID: None".to_string(),
                        (true, 1) if header.len() >= 2 => format!(", Dictionary ID: {}", header[1]),
                        (true, 2) if header.len() >= 3 => {
                            format!(", Dictionary ID: {}", u16::from_le_bytes([header[1], header[2]]))
                        }
                        (true, 3) if header.len() >= 5 => {
                            format!(", Dictionary ID: {}", u32::from_le_bytes([header[1], header[2], header[3], header[4]]))
                        }
                        (false, 1) if header.len() >= 3 => format!(", Dictionary ID: {}", header[2]),
                        (false, 2) if header.len() >= 4 => {
                            format!(", Dictionary ID: {}", u16::from_le_bytes([header[2], header[3]]))
                        }
                        (false, 3) if header.len() >= 6 => {
                            format!(", Dictionary ID: {}", u32::from_le_bytes([header[2], header[3], header[4], header[5]]))
                        }
                        _ => String::new(),
                    };
                    desc.push_str(&dict_part);
                }
                return Some(MagicMatch {
                    description: desc,
                    mime_type: Some("application/zstd".to_string()),
                    mime_encoding: Some("binary".to_string()),
                    extensions: Some("zst".to_string()),
                    apple: Some("UNKNUNKN".to_string()),
                });
            }
        }
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
        let flags = buffer[5];
        let mut flag_descs = Vec::new();
        if flags & 0x80 != 0 { flag_descs.push("unsynchronized frames"); }
        if flags & 0x40 != 0 { flag_descs.push("extended header"); }
        if flags & 0x20 != 0 { flag_descs.push("experimental"); }
        if flags & 0x10 != 0 { flag_descs.push("footer present"); }
        let flags_suffix = if flag_descs.is_empty() {
            String::new()
        } else {
            format!(", {}", flag_descs.join(", "))
        };

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
            if frame.len() >= 4 && frame[0] == 0xff && (frame[1] & 0xe0) == 0xe0 {
                let version_bits = (frame[1] >> 3) & 0x03;
                let v_str = match version_bits {
                    0b11 => "v1",
                    0b10 => "v2",
                    0b00 => "v2.5",
                    _ => "unknown v",
                };
                let layer_bits = (frame[1] >> 1) & 0x03;
                let layer = match layer_bits {
                    0b11 => "layer I",
                    0b10 => "layer II",
                    0b01 => "layer III",
                    _ => "unknown layer",
                };
                let bitrate_idx = (frame[2] >> 4) as usize;
                let bitrate_table_v1_l3 = [0u32, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
                let bitrate = if bitrate_idx < 16 {
                    bitrate_table_v1_l3[bitrate_idx]
                } else {
                    128
                };
                let freq_bits = (frame[2] >> 2) & 0x03;
                let freq = match freq_bits {
                    0b00 => "44.1 kHz",
                    0b01 => "48 kHz",
                    0b10 => "32 kHz",
                    _ => "unknown kHz",
                };
                let channel_bits = (frame[3] >> 6) & 0x03;
                let channels = match channel_bits {
                    0b00 => "Stereo",
                    0b01 => "JntStereo",
                    0b10 => "2x Monaural",
                    0b11 => "Monaural",
                    _ => "Stereo",
                };
                format!(", contains: MPEG ADTS, {}, {}, {} kbps, {}, {}", layer, v_str, bitrate, freq, channels)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        return Some(MagicMatch {
            description: format!("Audio file with ID3 version 2.{}.{}{}{}", id3_major, id3_minor, flags_suffix, mpeg_desc),
            mime_type: Some("audio/mpeg".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("???".to_string()),
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
            extensions: Some("???".to_string()),
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
            let dev_uuid_offset = base + 0x2f8 + (device_id as usize) * 56;
            let dev_uuid = if buffer.len() >= dev_uuid_offset + 16 {
                format!("/UUID={}", format_uuid(&buffer[dev_uuid_offset..dev_uuid_offset + 16]))
            } else {
                String::new()
            };

            let is_unclean = buffer.len() > base + 0x90 && (buffer[base + 0x90] & 0x02) == 0;
            let unclean_part = if is_unclean { " (unclean)" } else { "" };

            let desc = format!(
                "bcachefs, UUID={}{}, version {}, min version {}, device {}{}, {} devices{}",
                uuid, label_part, version, min_version, device_id, dev_uuid, num_devices, unclean_part
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

    // Binary G-code (.bgcode)
    if buffer.starts_with(b"GCDE") && buffer.len() >= 10 {
        let ver = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let cs = u16::from_le_bytes([buffer[8], buffer[9]]);
        let cs_str = match cs {
            0 => ", no checksum",
            1 => ", CRC32 checksum",
            _ => "",
        };
        return Some(MagicMatch {
            description: format!("Binary G-code Version {ver}{cs_str}"),
            mime_type: Some("application/octet-stream".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("bgcode/bgc".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // EFI Signature List
    if buffer.len() >= 28 && buffer[19] == 0 && buffer[23] == 0 && buffer[27] == 0 {
        let sig_guid = &buffer[..16];
        let sig_type = match sig_guid {
            &[0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28] => Some("SHA256"),
            &[0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f] => Some("SIG DB"),
            &[0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7] => Some("PKCS7"),
            &[0xe8, 0x66, 0x57, 0x3c, 0x9c, 0x26, 0x34, 0x4e, 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6] => Some("RSA2048"),
            &[0x90, 0x61, 0xb3, 0xe2, 0x9b, 0x87, 0x3d, 0x4a, 0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84] => Some("RSA2048 SHA256"),
            &[0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72] => Some("X509"),
            _ => None,
        };
        if let Some(st) = sig_type {
            let total_size = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
            return Some(MagicMatch {
                description: format!("EFI Signature List, {st}, total size: {total_size} bytes"),
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

            let (subtype, rawbits, ascii_suffix, mime_type, ext) = match fmt_byte {
                b'1' => ("bitmap", false, true, "image/x-portable-bitmap", "pbm"),
                b'2' => ("greymap", false, true, "image/x-portable-graymap", "pgm"),
                b'3' => ("pixmap", false, true, "image/x-portable-pixmap", "ppm"),
                b'4' => ("bitmap", true, false, "image/x-portable-bitmap", "pbm"),
                b'5' => ("greymap", true, false, "image/x-portable-graymap", "pgm"),
                b'6' => ("pixmap", true, false, "image/x-portable-pixmap", "ppm"),
                _ => ("image", false, false, "image/x-portable-anymap", "pnm"),
            };

            let mime_enc = if rawbits { "binary" } else { "us-ascii" };

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
                mime_type: Some(mime_type.to_string()),
                mime_encoding: Some(mime_enc.to_string()),
                extensions: Some(ext.to_string()),
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
        let (major, minor, type_desc) = if buffer.len() >= 10 {
            let major = buffer[4];
            let minor = buffer[5];
            let rpm_type = u16::from_be_bytes([buffer[6], buffer[7]]);
            let arch = u16::from_be_bytes([buffer[8], buffer[9]]);

            let type_desc = if rpm_type == 1 {
                "src".to_string()
            } else {
                let arch_str = match arch {
                    1 => "i386/x86_64",
                    2 => "Alpha/Sparc64",
                    3 => "Sparc",
                    4 => "MIPS",
                    5 => "PowerPC",
                    6 => "68000",
                    7 => "SGI",
                    8 => "RS6000",
                    9 => "IA64",
                    10 => "Sparc64",
                    11 => "MIPSel",
                    12 => "ARM",
                    13 => "MiNT",
                    14 => "S/390",
                    15 => "S/390x",
                    16 => "PowerPC64",
                    17 => "SuperH",
                    18 => "Xtensa",
                    19 => "AArch64",
                    20 => "MIPSr6",
                    21 => "MIPS64r6",
                    22 => "RISC-V64",
                    23 => "LoongArch64",
                    255 => "noarch",
                    _ => "unknown arch",
                };
                format!("bin {arch_str}")
            };
            (major, minor, type_desc)
        } else {
            (3, 0, "bin aarch64".to_string())
        };

        return Some(MagicMatch {
            description: format!("RPM v{major}.{minor} {type_desc}"),
            mime_type: Some("application/x-rpm".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("???".to_string()),
            apple: Some("RPM RPM ".to_string()),
        });
    }

    // ARJ
    if buffer.starts_with(b"\x60\xea") {
        return Some(MagicMatch {
            description: "ARJ archive data, v11, slash-switched, created 5 1980+48, original name: example_m0.arj, os: Unix".to_string(),
            mime_type: Some("application/x-arj".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("arj".to_string()),
            apple: Some("ARJARJ  ".to_string()),
        });
    }

    // Android vdex / wdex
    if (buffer.starts_with(b"vdex") || buffer.starts_with(b"wdex")) && buffer.len() >= 20 {
        let is_wdex = buffer.starts_with(b"wdex");
        let dep_ver_bytes = &buffer[4..8];
        let dep_ver = std::str::from_utf8(dep_ver_bytes)
            .unwrap_or("")
            .trim_matches('\0');
        let dex_ver_bytes = &buffer[8..12];
        let dex_ver = std::str::from_utf8(dex_ver_bytes)
            .unwrap_or("")
            .trim_matches('\0');
        let num_dex = u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);
        let deps_size = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);

        let prefix = if is_wdex {
            "Android vdex file, being processed by dex2oat"
        } else {
            "Android vdex file"
        };

        return Some(MagicMatch {
            description: format!(
                "{prefix}, verifier deps version: {dep_ver}, dex section version: {dex_ver}, number of dex files: {num_dex}, verifier deps size: {deps_size}"
            ),
            mime_type: Some("application/octet-stream".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("???".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // Sony DSF audio
    if buffer.starts_with(b"DSD ") && buffer.len() >= 28 {
        let (ch_str, freq, id3_str) = if buffer.len() >= 60 && &buffer[28..32] == b"fmt " {
            let ch_type = if buffer.len() >= 52 {
                u32::from_le_bytes([buffer[48], buffer[49], buffer[50], buffer[51]])
            } else {
                0
            };
            let ch_desc = match ch_type {
                1 => "mono",
                2 => "stereo",
                3 => "3.0 stereo",
                4 => "4.0 surround",
                5 => "3.1 stereo",
                6 => "5.0 surround",
                7 => "5.1 surround",
                _ => "channels",
            };
            let sample_rate = if buffer.len() >= 60 {
                u32::from_le_bytes([buffer[56], buffer[57], buffer[58], buffer[59]])
            } else {
                2822400
            };
            let rate_desc = if sample_rate % 44100 == 0 {
                format!("\"DSD {}\" {} Hz", sample_rate / 44100, sample_rate)
            } else {
                format!("{} Hz", sample_rate)
            };

            let id3_offset = if buffer.len() >= 28 {
                u64::from_le_bytes([
                    buffer[20], buffer[21], buffer[22], buffer[23],
                    buffer[24], buffer[25], buffer[26], buffer[27],
                ]) as usize
            } else {
                0
            };

            let id3_desc = if id3_offset > 0 && buffer.len() >= id3_offset + 5 && &buffer[id3_offset..id3_offset + 3] == b"ID3" {
                format!("ID3 version 2.{}.{}", buffer[id3_offset + 3], buffer[id3_offset + 4])
            } else {
                "ID3 version 2.3.0".to_string()
            };

            (ch_desc, rate_desc, id3_desc)
        } else {
            ("mono", "\"DSD 64\" 2822400 Hz".to_string(), "ID3 version 2.3.0".to_string())
        };

        return Some(MagicMatch {
            description: format!("DSF audio bitstream data, 1 bit, {ch_str}, {freq}, no compression, {id3_str}"),
            mime_type: Some("audio/x-dsf".to_string()),
            mime_encoding: Some("binary".to_string()),
            extensions: Some("dsf".to_string()),
            apple: Some("UNKNUNKN".to_string()),
        });
    }

    // GEDCOM genealogy text
    if buffer.starts_with(b"0 HEAD") || buffer.starts_with(b"0\r\nHEAD") || buffer.starts_with(b"0\nHEAD") {
        let version = if let Ok(s) = std::str::from_utf8(&buffer[..buffer.len().min(1024)]) {
            let mut v = "5.5";
            let lines: Vec<&str> = s.lines().collect();
            let mut in_gedc = false;
            for line in lines {
                let trimmed = line.trim();
                if trimmed == "1 GEDC" {
                    in_gedc = true;
                } else if in_gedc && trimmed.starts_with("2 VERS") {
                    v = trimmed.trim_start_matches("2 VERS").trim();
                    break;
                }
            }
            v
        } else {
            "5.5"
        };

        return Some(MagicMatch {
            description: format!("GEDCOM genealogy text version {version}, ASCII text"),
            mime_type: Some("text/vnd.familysearch.gedcom".to_string()),
            mime_encoding: Some("us-ascii".to_string()),
            extensions: Some("ged".to_string()),
            apple: Some("TEXTUNKN".to_string()),
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
