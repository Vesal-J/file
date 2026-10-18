// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

pub mod ast;
pub mod builtin_db;
pub mod evaluator;
mod mgc;
pub mod parser;

use crate::config::Config;
pub use ast::MagicRule;
pub use evaluator::MagicMatch;

pub struct MagicDatabase {
    pub custom_rules: Vec<MagicRule>,
}

impl MagicDatabase {
    pub fn new() -> Self {
        Self {
            custom_rules: Vec::new(),
        }
    }

    pub fn load_file(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let original_len = self.custom_rules.len();
        let result = (|| {
            let metadata = std::fs::metadata(path)?;
            if metadata.is_dir() {
                // libmagic's apprentice loader reads regular files in a magic
                // directory in lexical order and ignores dotfiles.
                let mut files = std::fs::read_dir(path)?
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|entry| {
                        entry
                            .file_name()
                            .is_some_and(|name| !name.to_string_lossy().starts_with('.'))
                            && entry.metadata().is_ok_and(|metadata| metadata.is_file())
                    })
                    .collect::<Vec<_>>();
                files.sort();
                for file in files {
                    self.load_database_file(&file)?;
                }
            } else {
                self.load_database_file(path)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.custom_rules.truncate(original_len);
            return Err(error);
        }
        self.sort_rules();
        Ok(())
    }

    fn load_database_file(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let bytes = std::fs::read(path)?;
        if bytes.starts_with(b"\x1c\x04\x1e\xf1") || bytes.starts_with(b"\xf1\x1e\x04\x1c") {
            let rules = mgc::parse(&bytes)?;
            self.custom_rules.extend(rules);
            return Ok(());
        }
        let content = String::from_utf8(bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let rules = parser::parse_magic_file(&content);
        self.custom_rules.extend(rules);
        Ok(())
    }

    /// Sort custom rules by apprentice strength (descending), tie-breaking by offset.
    pub fn sort_rules(&mut self) {
        self.custom_rules.sort_by(|a, b| {
            let sa = a.strength();
            let sb = b.strength();
            if sa != sb {
                sb.cmp(&sa) // descending by strength
            } else {
                let off_a = match a.offset {
                    ast::Offset::Direct(n) => n as isize,
                    ast::Offset::Relative(n) => n,
                    ast::Offset::Indirect { base, .. } => base as isize,
                };
                let off_b = match b.offset {
                    ast::Offset::Direct(n) => n as isize,
                    ast::Offset::Relative(n) => n,
                    ast::Offset::Indirect { base, .. } => base as isize,
                };
                off_b.cmp(&off_a) // higher offset first
            }
        });
    }

    /// Evaluate buffer against magic rules.
    ///
    /// When `config.keep_going` is true (-k flag), collect ALL matching rules
    /// and join them with the upstream separator `\012- ` (octalified form of
    /// the literal newline + "- " that upstream `file_separator()` emits).
    pub fn evaluate(&self, buffer: &[u8], config: &Config) -> Option<MagicMatch> {
        if config.keep_going && !self.custom_rules.is_empty() {
            // Collect all matching rules
            let mut evaluator = evaluator::Evaluator::new(buffer, config);
            let matches = evaluator.evaluate_rules_keep_going(&self.custom_rules);
            if !matches.is_empty() {
                // Join descriptions with upstream separator \012- (octal-escaped newline + "- ")
                let desc = matches
                    .iter()
                    .map(|m| m.description.as_str())
                    .collect::<Vec<_>>()
                    .join("\\012- ");

                // Use metadata from first match, upgraded by later matches
                let mut merged = matches
                    .into_iter()
                    .reduce(|mut acc, m| {
                        if m.mime_type.is_some() {
                            acc.mime_type = m.mime_type;
                        }
                        if m.mime_encoding.is_some() {
                            acc.mime_encoding = m.mime_encoding;
                        }
                        if m.extensions.is_some() {
                            acc.extensions = m.extensions;
                        }
                        if m.apple.is_some() {
                            acc.apple = m.apple;
                        }
                        acc
                    })
                    .unwrap();
                merged.description = desc;
                return Some(merged);
            }
            // Fall through to fast path if no custom rules matched
        } else if !self.custom_rules.is_empty() {
            let mut evaluator = evaluator::Evaluator::new(buffer, config);
            if let Some(m) = evaluator.evaluate_rules(&self.custom_rules) {
                return Some(m);
            }
        }

        // Keep the hand-written Rust fast paths as a fallback for formats the
        // bundled source rules or the current parser do not recognize.
        builtin_db::check_fast_path(buffer)
    }
}

impl Default for MagicDatabase {
    fn default() -> Self {
        Self::new()
    }
}
