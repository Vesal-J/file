// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::config::{Config, TestKind};
use crate::decompress;
use crate::fs;
use crate::magic::MagicDatabase;
use crate::specialized;
use crate::text;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationResult {
    pub description: String,
    pub mime_type: String,
    pub mime_encoding: String,
    pub extensions: String,
    pub apple: String,
}

impl ClassificationResult {
    pub fn new(
        description: impl Into<String>,
        mime_type: impl Into<String>,
        mime_encoding: impl Into<String>,
        extensions: impl Into<String>,
        apple: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            mime_type: mime_type.into(),
            mime_encoding: mime_encoding.into(),
            extensions: extensions.into(),
            apple: apple.into(),
        }
    }

    pub fn empty() -> Self {
        Self::new("empty", "application/x-empty", "binary", "???", "UNKNUNKN")
    }

    pub fn fallback_data() -> Self {
        Self::new(
            "data",
            "application/octet-stream",
            "binary",
            "???",
            "UNKNUNKN",
        )
    }
}

pub fn classify_file(
    path: &Path,
    config: &Config,
    magic_db: &MagicDatabase,
) -> Result<ClassificationResult, std::io::Error> {
    // Stdin handling
    if path == Path::new("-") {
        let mut buffer = Vec::new();
        let stdin = std::io::stdin();
        let mut handle = stdin.lock().take(config.params.bytes as u64);
        handle.read_to_end(&mut buffer)?;
        return classify_buffer(&buffer, config, magic_db);
    }

    // 1. Filesystem Tests
    if let Some(fs_res) = fs::test_filesystem(path, config)? {
        return Ok(ClassificationResult::new(
            fs_res.description,
            fs_res.mime_type,
            fs_res.mime_encoding,
            fs_res.extensions,
            fs_res.apple,
        ));
    }

    // 2. Open and Read Bounded Header
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };
    let mut buffer = Vec::new();
    let mut take_handle = (&mut file).take(config.params.bytes as u64);
    if let Err(e) = take_handle.read_to_end(&mut buffer) {
        return Err(e);
    }

    let mut res = classify_buffer_with_path(&buffer, config, magic_db, Some(path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta_opt = if config.dereference {
            std::fs::metadata(path).ok()
        } else {
            std::fs::symlink_metadata(path).ok()
        };
        if let Some(meta) = meta_opt {
            let mode = meta.mode();
            let mut parts = Vec::new();
            if (mode & 0o4000) != 0 {
                parts.push("setuid");
            }
            if (mode & 0o2000) != 0 {
                parts.push("setgid");
            }
            if (mode & 0o1000) != 0 {
                parts.push("sticky");
            }
            if !parts.is_empty() {
                res.description = format!("{} {}", parts.join(", "), res.description);
            }
        }
    }

    Ok(res)
}

pub fn classify_buffer(
    buffer: &[u8],
    config: &Config,
    magic_db: &MagicDatabase,
) -> Result<ClassificationResult, std::io::Error> {
    classify_buffer_with_path(buffer, config, magic_db, None)
}

pub fn classify_buffer_with_path(
    buffer: &[u8],
    config: &Config,
    magic_db: &MagicDatabase,
    path: Option<&Path>,
) -> Result<ClassificationResult, std::io::Error> {
    if buffer.is_empty() {
        return Ok(ClassificationResult::empty());
    }

    // 3. Decompression (-z or -Z)
    let (decompressed_data, comp_type_opt) = if (config.uncompress || config.uncompress_noreport)
        && !config.exclude_tests.contains(&TestKind::Compress)
    {
        decompress::try_decompress(buffer)
    } else {
        (Vec::new(), None)
    };

    let inspected_buf = if !decompressed_data.is_empty() {
        &decompressed_data[..]
    } else {
        buffer
    };

    // 4. Structured Format Tests
    if !config.exclude_tests.contains(&TestKind::Tar) {
        if let Some(tar_res) = specialized::test_tar(inspected_buf) {
            return Ok(wrap_decompressed(
                ClassificationResult::new(
                    tar_res.description,
                    tar_res.mime_type,
                    tar_res.mime_encoding,
                    tar_res.extensions,
                    tar_res.apple,
                ),
                comp_type_opt,
                config,
            ));
        }
    }

    if !config.exclude_tests.contains(&TestKind::Json) {
        if let Some(json_res) = specialized::test_json(inspected_buf) {
            return Ok(wrap_decompressed(
                ClassificationResult::new(
                    json_res.description,
                    json_res.mime_type,
                    json_res.mime_encoding,
                    json_res.extensions,
                    json_res.apple,
                ),
                comp_type_opt,
                config,
            ));
        }
    }

    if !config.exclude_tests.contains(&TestKind::Csv) {
        if let Some(csv_res) = specialized::test_csv(inspected_buf) {
            return Ok(wrap_decompressed(
                ClassificationResult::new(
                    csv_res.description,
                    csv_res.mime_type,
                    csv_res.mime_encoding,
                    csv_res.extensions,
                    csv_res.apple,
                ),
                comp_type_opt,
                config,
            ));
        }
    }

    if !config.exclude_tests.contains(&TestKind::Cdf) {
        if let Some(cdf_res) = specialized::test_cdf(inspected_buf) {
            return Ok(wrap_decompressed(
                ClassificationResult::new(
                    cdf_res.description,
                    cdf_res.mime_type,
                    cdf_res.mime_encoding,
                    cdf_res.extensions,
                    cdf_res.apple,
                ),
                comp_type_opt,
                config,
            ));
        }
    }

    if !config.exclude_tests.contains(&TestKind::Elf) {
        if let Some(elf_res) = specialized::test_elf_with_path(inspected_buf, config, path) {
            return Ok(wrap_decompressed(
                ClassificationResult::new(
                    elf_res.description,
                    elf_res.mime_type,
                    elf_res.mime_encoding,
                    elf_res.extensions,
                    elf_res.apple,
                ),
                comp_type_opt,
                config,
            ));
        }
    }

    // 5. Soft Magic Database Tests
    let magic_match = if !config.exclude_tests.contains(&TestKind::Soft) {
        magic_db.evaluate(inspected_buf, config)
    } else {
        None
    };

    if let Some(magic_res) = magic_match {
        let mut desc = magic_res.description;
        let mut mime_type = magic_res
            .mime_type
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let mut mime_encoding = magic_res
            .mime_encoding
            .unwrap_or_else(|| "binary".to_string());
        let extensions = magic_res.extensions.unwrap_or_else(|| "???".to_string());
        let apple = magic_res.apple.unwrap_or_else(|| "UNKNUNKN".to_string());

        // In keep_going mode (-k), also run text/encoding tests and append result
        if config.keep_going && !config.exclude_tests.contains(&TestKind::Ascii) {
            if let Some(text_res) = text::test_text(inspected_buf, config) {
                if !text_res.description.is_empty() {
                    desc.push_str(", ");
                    desc.push_str(&text_res.description);
                }
                if mime_type == "application/octet-stream" {
                    mime_type = text_res.mime_type;
                    mime_encoding = text_res.mime_encoding;
                }
            }
        }

        if mime_encoding == "binary" && !config.exclude_tests.contains(&TestKind::Ascii) {
            if let Some(text_res) = text::test_text(inspected_buf, config) {
                mime_encoding = text_res.mime_encoding;
            }
            if inspected_buf.starts_with(b"#!") {
                mime_encoding =
                    text::encoding::detect_encoding(inspected_buf, config.params.encoding)
                        .0
                        .mime_encoding()
                        .to_string();
            }
        }

        return Ok(wrap_decompressed(
            ClassificationResult::new(desc, mime_type, mime_encoding, extensions, apple),
            comp_type_opt,
            config,
        ));
    }

    // 6. Text & Encoding Tests
    if !config.exclude_tests.contains(&TestKind::Ascii) {
        if let Some(mut text_res) = text::test_text(inspected_buf, config) {
            if path
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                == Some("irbrc")
            {
                text_res.description = format!(
                    "Ruby script text, {} text",
                    text::encoding::detect_encoding(inspected_buf, config.params.encoding)
                        .0
                        .name()
                );
                text_res.mime_type = "text/x-ruby".to_string();
            }
            return Ok(wrap_decompressed(
                ClassificationResult::new(
                    text_res.description,
                    text_res.mime_type,
                    text_res.mime_encoding,
                    text_res.extensions,
                    text_res.apple,
                ),
                comp_type_opt,
                config,
            ));
        }
    }

    // Check for binary script executable (e.g. #! in binary files)
    if inspected_buf.starts_with(b"#!") {
        let first_line_end = inspected_buf
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
            .unwrap_or(inspected_buf.len());
        if let Ok(first_line) = std::str::from_utf8(&inspected_buf[2..first_line_end]) {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if let Some(&interpreter) = parts.first() {
                return Ok(wrap_decompressed(
                    ClassificationResult::new(
                        format!("a {interpreter} script executable (binary data)"),
                        "application/octet-stream".to_string(),
                        "binary".to_string(),
                        "???".to_string(),
                        "UNKNUNKN".to_string(),
                    ),
                    comp_type_opt,
                    config,
                ));
            }
        }
    }

    // 7. Fallback: data
    Ok(wrap_decompressed(
        ClassificationResult::fallback_data(),
        comp_type_opt,
        config,
    ))
}

fn wrap_decompressed(
    mut res: ClassificationResult,
    comp_type_opt: Option<&'static str>,
    config: &Config,
) -> ClassificationResult {
    if let Some(comp) = comp_type_opt {
        if config.uncompress && !config.uncompress_noreport {
            res.description = format!("{comp} ({})", res.description);
        }
    }
    res
}
