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
    let mut desc_parts = res.description.split("\n@@MACHO_ARCH@@");
    let base_description = desc_parts.next().unwrap_or("");
    let architecture_rows: Vec<(&str, &str)> = desc_parts
        .filter_map(|entry| entry.split_once("@@"))
        .collect();
    let content = if config.apple {
        res.apple.clone()
    } else if config.extension {
        res.extensions.clone()
    } else {
        match config.mime_mode {
            MimeMode::All if !architecture_rows.is_empty() => res.mime_type.clone(),
            MimeMode::All => format!("{}; charset={}", res.mime_type, res.mime_encoding),
            MimeMode::TypeOnly => res.mime_type.clone(),
            MimeMode::EncodingOnly => res.mime_encoding.clone(),
            MimeMode::None => base_description.to_string(),
        }
    };

    let formatted_content = if config.raw {
        content.clone()
    } else {
        escape_octal(&content)
    };

    let mut output = if config.brief {
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
                " ".repeat(padding - escaped_filename.len() + 1)
            } else {
                " ".to_string()
            };
            format!(
                "{escaped_filename}{}{pad_spaces}{formatted_content}",
                config.separator
            )
        }
    };

    if !config.print0 {
        let arch_path = filename;
        let include_arch_rows = !config.apple
            && !config.extension
            && matches!(
                config.mime_mode,
                MimeMode::None | MimeMode::All | MimeMode::TypeOnly
            );
        if include_arch_rows {
            for (index, (arch, description)) in architecture_rows.into_iter().enumerate() {
                let mut row = match config.mime_mode {
                    MimeMode::None => description.to_string(),
                    MimeMode::All => format!("{}; charset={}", res.mime_type, res.mime_encoding),
                    MimeMode::TypeOnly => res.mime_type.clone(),
                    MimeMode::EncodingOnly => res.mime_encoding.clone(),
                };
                if config.mime_mode == MimeMode::All && index > 0 {
                    row.push_str(&format!("; charset={}", res.mime_encoding));
                }
                let description = if config.raw { row } else { escape_octal(&row) };
                output.push_str(&format!(
                    "\n{arch_path} (for architecture {arch}):\t{description}"
                ));
            }
        }
    }

    output
}

pub fn print_and_flush(output: &str, config: &Config) {
    println!("{output}");
    if config.no_buffer {
        let _ = std::io::stdout().flush();
    }
}

fn escape_octal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            out.push_str(&format!("\\{:03o}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}
