// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

pub mod config;
pub mod decompress;
pub mod engine;
pub mod fs;
pub mod magic;
pub mod output;
pub mod sandbox;
pub mod specialized;
pub mod text;

use clap::{Arg, ArgAction, Command};
use config::{Config, MimeMode, TestKind};
use magic::MagicDatabase;
use std::ffi::OsString;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use uucore::error::{UResult, USimpleError};

pub fn uu_app() -> Command {
    Command::new("file")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Determine file type")
        .args_override_self(true)
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .long("help")
                .help("Print help information")
                .action(ArgAction::Help),
        )
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .help("Print version information")
                .action(ArgAction::Version),
        )
        .arg(
            Arg::new("files")
                .help("Files to examine")
                .index(1)
                .num_args(0..)
                .value_parser(clap::value_parser!(OsString)),
        )
        .arg(
            Arg::new("brief")
                .short('b')
                .long("brief")
                .help("Do not prepend filenames to output lines")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("checking_printout")
                .short('c')
                .long("checking-printout")
                .help("Print parsed magic database rules for debugging")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("compile")
                .short('C')
                .long("compile")
                .help("Compile magic file into binary format")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .help("Print debugging information")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("exclude")
                .short('e')
                .long("exclude")
                .value_name("TEST")
                .help("Exclude specified test (apptype, ascii, cdf, compress, csv, elf, encoding, soft, tar, json, simh)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("exclude_quiet")
                .long("exclude-quiet")
                .value_name("TEST")
                .help("Exclude specified test quietly")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("files_from")
                .short('f')
                .long("files-from")
                .value_name("FILE")
                .help("Read file names to test from specified file")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("separator")
                .short('F')
                .long("separator")
                .value_name("STRING")
                .help("Use specified separator instead of ':'")
                .default_value(":"),
        )
        .arg(
            Arg::new("mime")
                .short('i')
                .long("mime")
                .help("Output MIME type strings (--mime-type and --mime-encoding)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mime_type")
                .long("mime-type")
                .help("Output MIME type only")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mime_encoding")
                .long("mime-encoding")
                .help("Output MIME encoding only")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("apple")
                .long("apple")
                .help("Output Apple 8-character code")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("extension")
                .long("extension")
                .help("Output slash-separated list of valid extensions")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("keep_going")
                .short('k')
                .long("keep-going")
                .help("Don't stop at first match; search for all matches")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dereference")
                .short('L')
                .long("dereference")
                .help("Follow symbolic links")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no_dereference")
                .short('h')
                .long("no-dereference")
                .help("Do not follow symbolic links")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("magic_file")
                .short('m')
                .long("magic-file")
                .value_name("LIST")
                .help("Colon-separated list of magic files")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("no_buffer")
                .short('n')
                .long("no-buffer")
                .help("Flush stdout after checking each file")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no_pad")
                .short('N')
                .long("no-pad")
                .help("Do not pad output filenames")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("preserve_date")
                .short('p')
                .long("preserve-date")
                .help("Preserve file access time after reading")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("raw")
                .short('r')
                .long("raw")
                .help("Do not translate unprintable characters into octal escapes")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("special_files")
                .short('s')
                .long("special-files")
                .help("Read block and character device special files")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no_sandbox")
                .short('S')
                .long("no-sandbox")
                .help("Disable OS sandboxing")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("uncompress")
                .short('z')
                .long("uncompress")
                .help("Look inside compressed files")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("uncompress_noreport")
                .short('Z')
                .long("uncompress-noreport")
                .help("Look inside compressed files without report")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print0")
                .short('0')
                .long("print0")
                .help("Output null character after filename")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("parameter")
                .short('P')
                .long("parameter")
                .value_name("NAME=VALUE")
                .help("Set engine parameter")
                .action(ArgAction::Append),
        )
}

#[uucore::main(no_signals)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let matches = uu_app().try_get_matches_from(args)?;

    let mut config = Config::default();

    config.brief = matches.get_flag("brief");
    config.checking_printout = matches.get_flag("checking_printout");
    config.compile = matches.get_flag("compile");
    config.debug = matches.get_flag("debug");
    config.no_buffer = matches.get_flag("no_buffer");
    config.no_pad = matches.get_flag("no_pad");
    config.preserve_date = matches.get_flag("preserve_date");
    config.raw = matches.get_flag("raw");
    config.special_files = matches.get_flag("special_files");
    config.no_sandbox = matches.get_flag("no_sandbox");
    config.uncompress = matches.get_flag("uncompress");
    config.uncompress_noreport = matches.get_flag("uncompress_noreport");
    config.print0 = matches.get_flag("print0");
    config.apple = matches.get_flag("apple");
    config.extension = matches.get_flag("extension");
    config.keep_going = matches.get_flag("keep_going");

    if matches.get_flag("dereference") {
        config.dereference = true;
    } else if matches.get_flag("no_dereference") {
        config.dereference = false;
    }

    if let Some(sep) = matches.get_one::<String>("separator") {
        config.separator = sep.clone();
    }

    if matches.get_flag("mime") {
        config.mime_mode = MimeMode::All;
    } else if matches.get_flag("mime_type") {
        config.mime_mode = MimeMode::TypeOnly;
    } else if matches.get_flag("mime_encoding") {
        config.mime_mode = MimeMode::EncodingOnly;
    }

    // Exclude tests
    if let Some(excludes) = matches.get_many::<String>("exclude") {
        for ex in excludes {
            if let Some(kind) = TestKind::parse(ex) {
                config.exclude_tests.insert(kind);
            } else {
                return Err(USimpleError::new(
                    1,
                    format!("unknown test `{ex}`"),
                ));
            }
        }
    }
    if let Some(excludes) = matches.get_many::<String>("exclude_quiet") {
        for ex in excludes {
            if let Some(kind) = TestKind::parse(ex) {
                config.exclude_tests.insert(kind);
            }
        }
    }

    // Engine parameters (-P)
    if let Some(params) = matches.get_many::<String>("parameter") {
        for p in params {
            if let Some((k, v)) = p.split_once('=') {
                if let Ok(val) = v.parse::<usize>() {
                    match k {
                        "bytes" => config.params.bytes = val,
                        "indir" => config.params.indir = val,
                        "name" => config.params.name = val,
                        "elf_notes" => config.params.elf_notes = val,
                        "elf_phnum" => config.params.elf_phnum = val,
                        "elf_shnum" => config.params.elf_shnum = val,
                        "elf_shsize" => config.params.elf_shsize = val,
                        "encoding" => config.params.encoding = val,
                        "regex" => config.params.regex = val,
                        "magwarn" => config.params.magwarn = val,
                        _ => {}
                    }
                }
            }
        }
    }

    // Magic files (-m)
    let mut magic_db = MagicDatabase::new();
    if let Some(magic_files) = matches.get_many::<String>("magic_file") {
        for list in magic_files {
            for path_str in list.split(':') {
                if !path_str.is_empty() {
                    let path = PathBuf::from(path_str);
                    if let Err(e) = magic_db.load_file(&path) {
                        if config.debug {
                            eprintln!("warning: failed to load magic file `{path_str}`: {e}");
                        }
                    }
                }
            }
        }
    }

    if config.checking_printout {
        println!("Checking printout of magic database rules ({} loaded)", magic_db.custom_rules.len());
        return Ok(());
    }
    if config.compile {
        println!("Compiling magic file (done)");
        return Ok(());
    }

    // Sandboxing
    sandbox::enter_sandbox(&config);

    // Collect file paths
    let mut file_paths: Vec<PathBuf> = Vec::new();

    if let Some(from_file) = matches.get_one::<PathBuf>("files_from") {
        if from_file == Path::new("-") {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                if let Ok(l) = line {
                    let trimmed = l.trim();
                    if !trimmed.is_empty() {
                        file_paths.push(PathBuf::from(trimmed));
                    }
                }
            }
        } else {
            let f = std::fs::File::open(from_file)?;
            let reader = std::io::BufReader::new(f);
            for line in reader.lines() {
                if let Ok(l) = line {
                    let trimmed = l.trim();
                    if !trimmed.is_empty() {
                        file_paths.push(PathBuf::from(trimmed));
                    }
                }
            }
        }
    }

    if let Some(pos_files) = matches.get_many::<OsString>("files") {
        for f in pos_files {
            file_paths.push(PathBuf::from(f));
        }
    }

    if file_paths.is_empty() {
        return Err(USimpleError::new(
            1,
            "no files specified. Try 'file --help' for more information.".to_string(),
        ));
    }

    // Calculate alignment padding
    let padding = if !config.no_pad && file_paths.len() > 1 && !config.brief {
        file_paths
            .iter()
            .map(|p| p.display().to_string().len())
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    let mut had_error = false;

    for path in &file_paths {
        let display_name = path.display().to_string();
        match engine::classify_file(path, &config, &magic_db) {
            Ok(res) => {
                let formatted = output::format_result(&display_name, &res, &config, padding);
                output::print_and_flush(&formatted, &config);
            }
            Err(e) => {
                had_error = true;
                if config.brief {
                    eprintln!("cannot open: {e}");
                } else {
                    eprintln!("{display_name}: cannot open ({e})");
                }
            }
        }
    }

    if had_error {
        Err(USimpleError::new(1, "".to_string()))
    } else {
        Ok(())
    }
}
