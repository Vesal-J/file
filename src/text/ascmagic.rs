// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::config::Config;
use crate::text::encoding::detect_encoding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextResult {
    pub description: String,
    pub mime_type: String,
    pub mime_encoding: String,
    pub extensions: String,
    pub apple: String,
}

impl TextResult {
    pub fn new(
        description: impl Into<String>,
        mime_type: impl Into<String>,
        mime_encoding: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            mime_type: mime_type.into(),
            mime_encoding: mime_encoding.into(),
            extensions: "???".to_string(),
            apple: "TEXTUNKN".to_string(),
        }
    }
}

pub fn test_text(buffer: &[u8], config: &Config) -> Option<TextResult> {
    let (charset, lines) = detect_encoding(buffer, config.params.encoding);
    if !charset.is_text() {
        return None;
    }

    let line_descs = lines.describe();
    let line_suffix = if line_descs.is_empty() {
        String::new()
    } else {
        format!(", {}", line_descs.join(", "))
    };

    let charset_name = charset.name();
    let mime_encoding = charset.mime_encoding();

    // 1. Check Shebang
    if let Some(shebang_res) = check_shebang(buffer, charset_name, mime_encoding, &line_suffix) {
        return Some(shebang_res);
    }

    // 2. Check languages, markup, scripts
    let scan = buffer.get(..buffer.len().min(8192)).unwrap_or(buffer);
    let decoded = match charset {
        crate::text::encoding::Charset::Utf16Le | crate::text::encoding::Charset::Utf16Be => {
            let data = if scan.starts_with(b"\xff\xfe") || scan.starts_with(b"\xfe\xff") { &scan[2..] } else { scan };
            let units = data.chunks_exact(2).map(|b| if charset == crate::text::encoding::Charset::Utf16Le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) });
            Some(String::from_utf16_lossy(&units.collect::<Vec<_>>()))
        }
        _ => std::str::from_utf8(scan).ok().map(str::to_owned),
    };
    if let Some(text) = decoded.as_deref() {
        let trimmed = text.trim_start();

        if let Some(header) = trimmed.strip_prefix("$ANSIBLE_VAULT;") {
            let header = header.lines().next().unwrap_or("");
            let fields: Vec<&str> = header.split(';').collect();
            if fields.len() >= 2 {
                return Some(TextResult {
                    description: format!("Ansible Vault, version {}, encryption {}", fields[0], fields[1]),
                    mime_type: "text/plain".to_string(),
                    mime_encoding: mime_encoding.to_string(),
                    extensions: "???".to_string(),
                    apple: "TEXT????".to_string(),
                });
            }
        }

        // HTML
        if trimmed.starts_with("<!DOCTYPE html")
            || trimmed.starts_with("<!doctype html")
            || trimmed.starts_with("<html")
            || trimmed.starts_with("<HTML")
        {
            return Some(TextResult {
                description: format!("HTML document, {charset_name} text{line_suffix}"),
                mime_type: "text/html".to_string(),
                mime_encoding: mime_encoding.to_string(),
                extensions: "???".to_string(),
                apple: "TEXThtml".to_string(),
            });
        }

        // XML / SVG
        if trimmed.starts_with("<?xml") || trimmed.starts_with("<?XML") {
            if text.contains("<osm") {
                return Some(TextResult {
                    description: format!("OpenStreetMap XML data, {charset_name} text{line_suffix}"),
                    mime_type: "text/plain".to_string(),
                    mime_encoding: mime_encoding.to_string(),
                    extensions: "???".to_string(),
                    apple: "TEXT????".to_string(),
                });
            }
            if text.contains("<svg") || text.contains("<SVG") {
                return Some(TextResult {
                    description: if matches!(charset, crate::text::encoding::Charset::Utf16Le | crate::text::encoding::Charset::Utf16Be) {
                        format!("SVG Scalable Vector Graphics image, Unicode text, UTF-16, {}-endian text", if charset == crate::text::encoding::Charset::Utf16Le { "little" } else { "big" })
                    } else { format!("SVG Scalable Vector Graphics image, {charset_name} text{line_suffix}") },
                    mime_type: "image/svg+xml".to_string(),
                    mime_encoding: mime_encoding.to_string(),
                    extensions: "svg".to_string(),
                    apple: "TEXTsvg ".to_string(),
                });
            }
            return Some(TextResult {
                description: format!("XML 1.0 document, {charset_name} text{line_suffix}"),
                mime_type: "text/xml".to_string(),
                mime_encoding: mime_encoding.to_string(),
                extensions: "???".to_string(),
                apple: "TEXTxml ".to_string(),
            });
        }

        if trimmed.starts_with("<svg") || trimmed.starts_with("<!DOCTYPE svg") || trimmed.starts_with("<!doctype svg") {
            return Some(TextResult {
                description: if matches!(charset, crate::text::encoding::Charset::Utf16Le | crate::text::encoding::Charset::Utf16Be) {
                    format!("SVG Scalable Vector Graphics image, Unicode text, UTF-16, {}-endian text", if charset == crate::text::encoding::Charset::Utf16Le { "little" } else { "big" })
                } else { format!("SVG Scalable Vector Graphics image, {charset_name} text{line_suffix}") },
                mime_type: "image/svg+xml".to_string(),
                mime_encoding: mime_encoding.to_string(),
                extensions: "svg".to_string(),
                apple: "TEXTsvg ".to_string(),
            });
        }

        // PostScript
        if trimmed.starts_with("%!PS-Adobe-") {
            return Some(TextResult {
                description: format!("PostScript document text, {charset_name} text{line_suffix}"),
                mime_type: "application/postscript".to_string(),
                mime_encoding: mime_encoding.to_string(),
                extensions: "ps".to_string(),
                apple: "TEXTPOST".to_string(),
            });
        }

        // Unified Diff
        if (trimmed.starts_with("--- ") && text.contains("\n+++ "))
            || (trimmed.starts_with("diff -") && text.contains("@@"))
        {
            return Some(TextResult {
                description: format!("unified diff output, {charset_name} text{line_suffix}"),
                mime_type: "text/x-diff".to_string(),
                mime_encoding: mime_encoding.to_string(),
                extensions: "diff/patch".to_string(),
                apple: "TEXTdiff".to_string(),
            });
        }

        // C / C++ source
        let has_include = text.contains("#include <")
            || text.contains("#include \"")
            || text.lines().any(|l| l.trim_start().starts_with("#include"));
        let has_c_ifdef = (text.contains("#ifdef ") || text.contains("#ifndef ")) && text.contains("#endif");
        let has_c_main = text.contains("int main(") || text.contains("void main(");

        if has_include || has_c_ifdef || has_c_main {
            let is_cpp = text.lines().any(|l| {
                let t = l.trim_start();
                t.starts_with("namespace ")
                    || t.starts_with("using namespace ")
                    || t.starts_with("template<")
                    || t.starts_with("template <")
                    || t.starts_with("class ")
            }) || text.contains("std::");

            if is_cpp {
                return Some(TextResult {
                    description: format!("C++ source, {charset_name} text{line_suffix}"),
                    mime_type: "text/x-c++".to_string(),
                    mime_encoding: mime_encoding.to_string(),
                    extensions: "???".to_string(),
                    apple: "TEXTc++ ".to_string(),
                });
            } else {
                return Some(TextResult {
                    description: format!("C source, {charset_name} text{line_suffix}"),
                    mime_type: "text/x-c".to_string(),
                    mime_encoding: mime_encoding.to_string(),
                    extensions: "???".to_string(),
                    apple: "TEXTc   ".to_string(),
                });
            }
        }
    }

    // 3. Fallback: plain text
    Some(TextResult {
        description: format!("{charset_name} text{line_suffix}"),
        mime_type: "text/plain".to_string(),
        mime_encoding: mime_encoding.to_string(),
        extensions: "???".to_string(),
        apple: "TEXTUNKN".to_string(),
    })
}

fn check_shebang(
    buffer: &[u8],
    charset_name: &str,
    mime_encoding: &str,
    line_suffix: &str,
) -> Option<TextResult> {
    if !buffer.starts_with(b"#!") {
        return None;
    }

    let end = memchr::memchr(b'\n', buffer).unwrap_or(buffer.len().min(256));
    let line = std::str::from_utf8(&buffer[2..end]).ok()?.trim();

    // Tokenize shebang line: e.g. "/usr/bin/env python3" or "/bin/bash -e"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let full_path = parts[0];
    let mut interpreter = full_path;
    if interpreter.ends_with("/env") && parts.len() > 1 {
        // Skip env flags like -S
        let mut idx = 1;
        while idx < parts.len() && parts[idx].starts_with('-') {
            idx += 1;
        }
        if idx < parts.len() {
            interpreter = parts[idx];
        }
    } else if let Some(last_slash) = interpreter.rfind('/') {
        interpreter = &interpreter[last_slash + 1..];
    }

    match interpreter {
        "sh" => Some(TextResult {
            description: format!("POSIX shell script, {charset_name} text executable{line_suffix}"),
            mime_type: "text/x-shellscript".to_string(),
            mime_encoding: mime_encoding.to_string(),
            extensions: "???".to_string(),
            apple: "TEXTsh  ".to_string(),
        }),
        "bash" => Some(TextResult {
            description: format!("Bourne-Again shell script, {charset_name} text executable{line_suffix}"),
            mime_type: "text/x-shellscript".to_string(),
            mime_encoding: mime_encoding.to_string(),
            extensions: "???".to_string(),
            apple: "TEXTbash".to_string(),
        }),
        s if s.starts_with("python") => Some(TextResult {
            description: format!("Python script, {charset_name} text executable{line_suffix}"),
            mime_type: "text/x-script.python".to_string(),
            mime_encoding: mime_encoding.to_string(),
            extensions: "???".to_string(),
            apple: "TEXTpy  ".to_string(),
        }),
        s if s.starts_with("perl") => Some(TextResult {
            description: format!("Perl script text executable{line_suffix}"),
            mime_type: "text/x-perl".to_string(),
            mime_encoding: mime_encoding.to_string(),
            extensions: "???".to_string(),
            apple: "TEXTpl  ".to_string(),
        }),
        s if s.starts_with("ruby") => Some(TextResult {
            description: format!("Ruby script, {charset_name} text executable{line_suffix}"),
            mime_type: "text/x-ruby".to_string(),
            mime_encoding: mime_encoding.to_string(),
            extensions: "???".to_string(),
            apple: "TEXTrb  ".to_string(),
        }),
        "node" | "nodejs" => Some(TextResult {
            description: format!("Node.js script, {charset_name} text executable{line_suffix}"),
            mime_type: "application/javascript".to_string(),
            mime_encoding: mime_encoding.to_string(),
            extensions: "???".to_string(),
            apple: "TEXTjs  ".to_string(),
        }),
        _ => Some(TextResult {
            description: format!("a {full_path} script, {charset_name} text executable{line_suffix}"),
            mime_type: "text/plain".to_string(),
            mime_encoding: mime_encoding.to_string(),
            extensions: "???".to_string(),
            apple: "TEXTUNKN".to_string(),
        }),
    }
}
