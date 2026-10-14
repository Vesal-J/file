// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Ascii,
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
    Iso8859,
    Binary,
}

impl Charset {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8 Unicode",
            Self::Utf8Bom => "UTF-8 Unicode (with BOM)",
            Self::Utf16Le => "Little-endian UTF-16 Unicode",
            Self::Utf16Be => "Big-endian UTF-16 Unicode",
            Self::Utf32Le => "Little-endian UTF-32 Unicode",
            Self::Utf32Be => "Big-endian UTF-32 Unicode",
            Self::Iso8859 => "ISO-8859",
            Self::Binary => "binary",
        }
    }

    pub fn mime_encoding(&self) -> &'static str {
        match self {
            Self::Ascii => "us-ascii",
            Self::Utf8 | Self::Utf8Bom => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Utf32Le => "utf-32le",
            Self::Utf32Be => "utf-32be",
            Self::Iso8859 => "iso-8859-1",
            Self::Binary => "binary",
        }
    }

    pub fn is_text(&self) -> bool {
        !matches!(self, Self::Binary)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineCharacteristics {
    pub has_crlf: bool,
    pub has_cr: bool,
    pub has_lf: bool,
    pub has_long_lines: bool,
    pub no_line_terminators: bool,
}

impl LineCharacteristics {
    pub fn describe(&self) -> Vec<&'static str> {
        let mut parts = Vec::new();

        if self.no_line_terminators {
            parts.push("with no line terminators");
        } else {
            let crlf = self.has_crlf;
            let cr = self.has_cr;
            let lf = self.has_lf;

            let terminators_count = (crlf as usize) + (cr as usize) + (lf as usize);
            if terminators_count > 1 {
                parts.push("with mixed line terminators");
            } else if crlf {
                parts.push("with CRLF line terminators");
            } else if cr {
                parts.push("with CR line terminators");
            }
            // lone LF is standard unix, so not specially mentioned in description
        }

        if self.has_long_lines {
            parts.push("with very long lines");
        }

        parts
    }
}

/// Detect the character set and line characteristics of a buffer.
pub fn detect_encoding(buffer: &[u8], max_bytes: usize) -> (Charset, LineCharacteristics) {
    let scan_len = buffer.len().min(max_bytes);
    let slice = &buffer[..scan_len];

    if slice.is_empty() {
        return (
            Charset::Ascii,
            LineCharacteristics {
                has_crlf: false,
                has_cr: false,
                has_lf: false,
                has_long_lines: false,
                no_line_terminators: true,
            },
        );
    }

    // 1. Check Byte Order Marks (BOM)
    if slice.starts_with(b"\xef\xbb\xbf") {
        let lines = analyze_lines(&slice[3..]);
        return (Charset::Utf8Bom, lines);
    }
    if slice.starts_with(b"\xff\xfe\x00\x00") {
        return (
            Charset::Utf32Le,
            LineCharacteristics {
                has_crlf: false,
                has_cr: false,
                has_lf: false,
                has_long_lines: false,
                no_line_terminators: false,
            },
        );
    }
    if slice.starts_with(b"\x00\x00\xfe\xff") {
        return (
            Charset::Utf32Be,
            LineCharacteristics {
                has_crlf: false,
                has_cr: false,
                has_lf: false,
                has_long_lines: false,
                no_line_terminators: false,
            },
        );
    }
    if slice.starts_with(b"\xff\xfe") {
        return (
            Charset::Utf16Le,
            LineCharacteristics {
                has_crlf: false,
                has_cr: false,
                has_lf: false,
                has_long_lines: false,
                no_line_terminators: false,
            },
        );
    }
    if slice.starts_with(b"\xfe\xff") {
        return (
            Charset::Utf16Be,
            LineCharacteristics {
                has_crlf: false,
                has_cr: false,
                has_lf: false,
                has_long_lines: false,
                no_line_terminators: false,
            },
        );
    }

    // 2. Check for UTF-16 without BOM (alternating null bytes)
    if slice.len() >= 4 {
        if slice[0] != 0 && slice[1] == 0 && slice[2] != 0 && slice[3] == 0 {
            return (
                Charset::Utf16Le,
                LineCharacteristics {
                    has_crlf: false,
                    has_cr: false,
                    has_lf: false,
                    has_long_lines: false,
                    no_line_terminators: false,
                },
            );
        }
        if slice[0] == 0 && slice[1] != 0 && slice[2] == 0 && slice[3] != 0 {
            return (
                Charset::Utf16Be,
                LineCharacteristics {
                    has_crlf: false,
                    has_cr: false,
                    has_lf: false,
                    has_long_lines: false,
                    no_line_terminators: false,
                },
            );
        }
    }

    // 3. Scan byte values
    let mut has_null = false;
    let mut has_high_bytes = false;
    let mut has_unprintable_control = false;

    for &b in slice {
        if b == 0 {
            has_null = true;
            break;
        }
        if b >= 0x80 {
            has_high_bytes = true;
        } else if b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0x1b | 0x08) {
            has_unprintable_control = true;
        }
    }

    // Binary file if null byte found or excessive unprintable control chars
    if has_null || has_unprintable_control {
        return (
            Charset::Binary,
            LineCharacteristics {
                has_crlf: false,
                has_cr: false,
                has_lf: false,
                has_long_lines: false,
                no_line_terminators: false,
            },
        );
    }

    let lines = analyze_lines(slice);

    if !has_high_bytes {
        (Charset::Ascii, lines)
    } else if std::str::from_utf8(slice).is_ok() {
        (Charset::Utf8, lines)
    } else {
        (Charset::Iso8859, lines)
    }
}

fn analyze_lines(slice: &[u8]) -> LineCharacteristics {
    let mut has_crlf = false;
    let mut has_cr = false;
    let mut has_lf = false;
    let mut has_long_lines = false;

    let mut current_line_len = 0;
    let mut i = 0;
    let len = slice.len();
    let mut saw_any_terminator = false;

    while i < len {
        let b = slice[i];
        if b == b'\r' {
            saw_any_terminator = true;
            if i + 1 < len && slice[i + 1] == b'\n' {
                has_crlf = true;
                i += 1;
            } else {
                has_cr = true;
            }
            if current_line_len > 300 {
                has_long_lines = true;
            }
            current_line_len = 0;
        } else if b == b'\n' {
            saw_any_terminator = true;
            has_lf = true;
            if current_line_len > 300 {
                has_long_lines = true;
            }
            current_line_len = 0;
        } else {
            current_line_len += 1;
        }
        i += 1;
    }

    if current_line_len > 300 {
        has_long_lines = true;
    }

    LineCharacteristics {
        has_crlf,
        has_cr,
        has_lf,
        has_long_lines,
        no_line_terminators: !saw_any_terminator,
    }
}
