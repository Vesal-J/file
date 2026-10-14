// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use std::collections::HashSet;
use std::path::PathBuf;

/// Engine tunables specified via `-P <name=value>`.
#[derive(Debug, Clone)]
pub struct Parameters {
    /// Maximum bytes read from input file into inspection buffer (default 7 MiB).
    pub bytes: usize,
    /// Maximum recursion limit for indirect magic rule offsets (default 50).
    pub indir: usize,
    /// Maximum call limit for `use`/`name` subroutine rules (default 150).
    pub name: usize,
    /// Maximum number of ELF notes processed (default 256).
    pub elf_notes: usize,
    /// Maximum number of ELF program section headers scanned (default 2,048).
    pub elf_phnum: usize,
    /// Maximum number of ELF section headers scanned (default 32,768).
    pub elf_shnum: usize,
    /// Maximum cumulative ELF section header size (default 128 MiB).
    pub elf_shsize: usize,
    /// Maximum bytes scanned during charset/text encoding determination (default 64 KiB).
    pub encoding: usize,
    /// Maximum byte length scanned during regex pattern matching (default 8,192).
    pub regex: usize,
    /// Maximum number of warnings emitted while compiling/loading magic rules before aborting.
    pub magwarn: usize,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            bytes: 7 * 1024 * 1024,
            indir: 50,
            name: 150,
            elf_notes: 256,
            elf_phnum: 2048,
            elf_shnum: 32768,
            elf_shsize: 128 * 1024 * 1024,
            encoding: 64 * 1024,
            regex: 8192,
            magwarn: 64,
        }
    }
}

/// Tests that can be excluded via `-e` / `--exclude`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestKind {
    Apptype,
    Ascii,
    Cdf,
    Compress,
    Csv,
    Elf,
    Encoding,
    Soft,
    Tar,
    Json,
    Simh,
}

impl TestKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "apptype" => Some(Self::Apptype),
            "ascii" => Some(Self::Ascii),
            "cdf" => Some(Self::Cdf),
            "compress" => Some(Self::Compress),
            "csv" => Some(Self::Csv),
            "elf" => Some(Self::Elf),
            "encoding" => Some(Self::Encoding),
            "soft" => Some(Self::Soft),
            "tar" => Some(Self::Tar),
            "json" => Some(Self::Json),
            "simh" => Some(Self::Simh),
            _ => None,
        }
    }
}

/// MIME output mode flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeMode {
    None,
    All,      // -i / --mime (both type and encoding)
    TypeOnly, // --mime-type
    EncodingOnly, // --mime-encoding
}

/// Runtime configuration parsed from CLI options.
#[derive(Debug, Clone)]
pub struct Config {
    pub brief: bool,
    pub checking_printout: bool,
    pub compile: bool,
    pub debug: bool,
    pub dereference: bool,
    pub exclude_tests: HashSet<TestKind>,
    pub files_from: Option<PathBuf>,
    pub separator: String,
    pub mime_mode: MimeMode,
    pub apple: bool,
    pub extension: bool,
    pub keep_going: bool,
    pub magic_files: Vec<PathBuf>,
    pub no_buffer: bool,
    pub no_pad: bool,
    pub preserve_date: bool,
    pub raw: bool,
    pub special_files: bool,
    pub no_sandbox: bool,
    pub uncompress: bool,
    pub uncompress_noreport: bool,
    pub print0: bool,
    pub params: Parameters,
}

impl Default for Config {
    fn default() -> Self {
        let posixly_correct = std::env::var_os("POSIXLY_CORRECT").is_some();
        Self {
            brief: false,
            checking_printout: false,
            compile: false,
            debug: false,
            // In POSIX mode, follow symlinks by default. Otherwise, do not follow.
            dereference: posixly_correct,
            exclude_tests: HashSet::new(),
            files_from: None,
            separator: ":".to_string(),
            mime_mode: MimeMode::None,
            apple: false,
            extension: false,
            keep_going: false,
            magic_files: Vec::new(),
            no_buffer: false,
            no_pad: false,
            preserve_date: false,
            raw: false,
            special_files: false,
            no_sandbox: false,
            uncompress: false,
            uncompress_noreport: false,
            print0: false,
            params: Parameters::default(),
        }
    }
}
