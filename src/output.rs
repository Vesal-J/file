// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::config::{Config, MimeMode};
use crate::engine::ClassificationResult;
use std::io::Write;

pub fn format_result(
    filename: &str,
    res: &ClassificationResult,
    config: &Config,
    padding: usize,
) -> String {
    let content = if config.apple {
        res.apple.clone()
    } else if config.extension {
        res.extensions.clone()
    } else {
        match config.mime_mode {
            MimeMode::All => {
                format!("{}; charset={}", res.mime_type, res.mime_encoding)
            }
            MimeMode::TypeOnly => res.mime_type.clone(),
            MimeMode::EncodingOnly => res.mime_encoding.clone(),
            MimeMode::None => res.description.clone(),
        }
    };

    let formatted_content = if config.raw {
        content
    } else {
        escape_octal(&content)
    };

    if config.brief {
        formatted_content
    } else {
        let escaped_filename = if config.raw {
            filename.to_string()
        } else {
            escape_octal(filename)
        };

        if config.print0 {
            format!("{escaped_filename}\0{formatted_content}")
        } else {
            let pad_spaces = if padding > escaped_filename.len() && !config.no_pad {
                " ".repeat(padding - escaped_filename.len())
            } else {
                String::new()
            };
            format!("{escaped_filename}{pad_spaces}{} {formatted_content}", config.separator)
        }
    }
}

pub fn print_and_flush(output: &str, config: &Config) {
    println!("{output}");
    if config.no_buffer {
        let _ = std::io::stdout().flush();
    }
}

fn escape_octal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r' {
            out.push_str(&format!("\\{:03o}", b));
        } else if b == 0x7f {
            out.push_str("\\177");
        } else {
            out.push(b as char);
        }
    }
    out
}
