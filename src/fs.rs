// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::config::Config;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsResult {
    pub description: String,
    pub mime_type: String,
    pub mime_encoding: String,
    pub extensions: String,
    pub apple: String,
}

impl FsResult {
    pub fn new(description: impl Into<String>, mime_type: impl Into<String>, mime_encoding: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            mime_type: mime_type.into(),
            mime_encoding: mime_encoding.into(),
            extensions: "???".to_string(),
            apple: "UNKNUNKN".to_string(),
        }
    }

    pub fn empty() -> Self {
        Self::new("empty", "application/x-empty", "binary")
    }

    pub fn directory() -> Self {
        Self::new("directory", "inode/directory", "binary")
    }

    pub fn socket() -> Self {
        Self::new("socket", "inode/socket", "binary")
    }

    pub fn fifo() -> Self {
        Self::new("fifo (named pipe)", "inode/fifo", "binary")
    }
}

/// Perform Phase 1 filesystem tests (stat/lstat, special files, directories, symlinks, empty).
/// Returns `Ok(Some(FsResult))` if classified by filesystem metadata,
/// `Ok(None)` if it is a non-empty regular file that should proceed to content inspection,
/// or `Err(io_error)` on failure.
pub fn test_filesystem(path: &Path, config: &Config) -> std::io::Result<Option<FsResult>> {
    // 1. Get symlink metadata first (does not follow symlinks)
    let symlink_meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    let file_type = symlink_meta.file_type();

    // 2. Handle symlinks
    if file_type.is_symlink() {
        if !config.dereference {
            // Describe the symlink itself
            let target = match fs::read_link(path) {
                Ok(t) => t.display().to_string(),
                Err(e) => return Err(e),
            };
            return Ok(Some(FsResult::new(
                format!("symbolic link to {target}"),
                "inode/symlink",
                "binary",
            )));
        } else {
            // Follow symlink: check target metadata
            match fs::metadata(path) {
                Ok(target_meta) => {
                    return inspect_target_metadata(path, &target_meta, config);
                }
                Err(_) => {
                    // Target does not exist -> broken symlink
                    let target = fs::read_link(path)
                        .map(|t| t.display().to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                    return Ok(Some(FsResult::new(
                        format!("broken symbolic link to {target}"),
                        "inode/symlink",
                        "binary",
                    )));
                }
            }
        }
    }

    // 3. Inspect non-symlink metadata
    inspect_target_metadata(path, &symlink_meta, config)
}

fn inspect_target_metadata(
    _path: &Path,
    meta: &fs::Metadata,
    config: &Config,
) -> std::io::Result<Option<FsResult>> {
    let file_type = meta.file_type();

    if file_type.is_dir() {
        return Ok(Some(FsResult::directory()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::fs::MetadataExt;

        if file_type.is_socket() {
            return Ok(Some(FsResult::socket()));
        }

        if file_type.is_fifo() {
            if !config.special_files {
                return Ok(Some(FsResult::fifo()));
            }
            // If special_files is true, proceed to read from FIFO
        }

        if file_type.is_char_device() {
            if !config.special_files {
                let rdev = meta.rdev();
                let major = (rdev >> 8) & 0xfff;
                let minor = (rdev & 0xff) | ((rdev >> 12) & 0xfff00);
                return Ok(Some(FsResult::new(
                    format!("character special ({major}/{minor})"),
                    "inode/chardevice",
                    "binary",
                )));
            }
        }

        if file_type.is_block_device() {
            if !config.special_files {
                let rdev = meta.rdev();
                let major = (rdev >> 8) & 0xfff;
                let minor = (rdev & 0xff) | ((rdev >> 12) & 0xfff00);
                return Ok(Some(FsResult::new(
                    format!("block special ({major}/{minor})"),
                    "inode/blockdevice",
                    "binary",
                )));
            }
        }
    }

    // If regular file and size == 0
    if meta.is_file() && meta.len() == 0 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
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
                return Ok(Some(FsResult::new(
                    format!("{}, empty", parts.join(", ")),
                    "application/x-empty",
                    "binary",
                )));
            }
        }
        return Ok(Some(FsResult::empty()));
    }

    // Proceed to content tests
    Ok(None)
}
