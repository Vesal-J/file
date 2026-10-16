// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::config::Config;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecializedResult {
    pub description: String,
    pub mime_type: String,
    pub mime_encoding: String,
    pub extensions: String,
    pub apple: String,
}

pub fn test_elf(buffer: &[u8], config: &Config) -> Option<SpecializedResult> {
    test_elf_with_path(buffer, config, None)
}

pub fn test_elf_with_path(
    buffer: &[u8],
    config: &Config,
    path: Option<&std::path::Path>,
) -> Option<SpecializedResult> {
    if buffer.len() < 52 || !buffer.starts_with(b"\x7fELF") {
        return None;
    }

    let class_byte = buffer[4]; // 1 = 32-bit, 2 = 64-bit
    let data_byte = buffer[5];  // 1 = LSB, 2 = MSB
    let is_64 = class_byte == 2;
    let is_lsb = data_byte == 1;

    let read_u16 = |buf: &[u8], offset: usize| -> Option<u16> {
        let b = buf.get(offset..offset + 2)?;
        Some(if is_lsb {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };

    let read_u32 = |buf: &[u8], offset: usize| -> Option<u32> {
        let b = buf.get(offset..offset + 4)?;
        Some(if is_lsb {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };

    let read_u64 = |buf: &[u8], offset: usize| -> Option<u64> {
        let b = buf.get(offset..offset + 8)?;
        Some(if is_lsb {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    };

    let class_desc = if is_64 { "64-bit" } else { "32-bit" };
    let data_desc = if is_lsb { "LSB" } else { "MSB" };

    let e_type = read_u16(buffer, 16)?;
    let e_machine = read_u16(buffer, 18)?;
    let osabi = buffer.get(7).copied().unwrap_or(0);

    let osabi_desc = match osabi {
        0 => "SYSV",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "GNU/Linux",
        6 => "Solaris",
        7 => "AIX",
        8 => "IRIX",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "UNIX - System V",
    };

    let machine_desc = match e_machine {
        0x03 => "Intel 80386",
        0x28 => "ARM",
        0x3e => "x86-64",
        0xb7 => "ARM aarch64",
        0xf3 => "RISC-V",
        0x14 => "PowerPC",
        0x15 => "PowerPC or cisco 7500",
        0x08 => "MIPS",
        0x02 => "SPARC",
        0x16 => "IBM S/390",
        _ => "unknown arch",
    };

    // Program headers inspection (interpreter, build id, dynamic)
    let (phoff, phentsize, phnum) = if is_64 {
        let phoff = read_u64(buffer, 32).unwrap_or(0) as usize;
        let phentsize = read_u16(buffer, 54).unwrap_or(0) as usize;
        let phnum = read_u16(buffer, 56).unwrap_or(0) as usize;
        (phoff, phentsize, phnum)
    } else {
        let phoff = read_u32(buffer, 28).unwrap_or(0) as usize;
        let phentsize = read_u16(buffer, 42).unwrap_or(0) as usize;
        let phnum = read_u16(buffer, 44).unwrap_or(0) as usize;
        (phoff, phentsize, phnum)
    };

    let mut interpreter = None;
    let mut build_id = None;
    let mut os_version = None;
    let mut has_dynamic = false;
    let mut has_pie_flag = false;
    let mut need_count = 0;

    let scan_phnum = phnum.min(config.params.elf_phnum);
    if phoff > 0 && phentsize >= 32 && phoff < buffer.len() {
        for i in 0..scan_phnum {
            let ph_start = phoff + i * phentsize;
            if ph_start + phentsize > buffer.len() {
                break;
            }
            let p_type = read_u32(buffer, ph_start).unwrap_or(0);

            if p_type == 2 {
                // PT_DYNAMIC
                has_dynamic = true;
                let (p_offset, p_filesz) = if is_64 {
                    (
                        read_u64(buffer, ph_start + 8).unwrap_or(0) as usize,
                        read_u64(buffer, ph_start + 32).unwrap_or(0) as usize,
                    )
                } else {
                    (
                        read_u32(buffer, ph_start + 4).unwrap_or(0) as usize,
                        read_u32(buffer, ph_start + 16).unwrap_or(0) as usize,
                    )
                };
                let entry_size = if is_64 { 16 } else { 8 };
                if p_offset < buffer.len() {
                    let dyn_slice = &buffer[p_offset..(p_offset + p_filesz).min(buffer.len())];
                    let num_entries = dyn_slice.len() / entry_size;
                    for idx in 0..num_entries {
                        let off = idx * entry_size;
                        let (tag, val) = if is_64 {
                            (
                                read_u64(dyn_slice, off).unwrap_or(0),
                                read_u64(dyn_slice, off + 8).unwrap_or(0),
                            )
                        } else {
                            (
                                read_u32(dyn_slice, off).unwrap_or(0) as u64,
                                read_u32(dyn_slice, off + 4).unwrap_or(0) as u64,
                            )
                        };
                        if tag == 0 {
                            break;
                        }
                        if tag == 1 {
                            need_count += 1;
                        }
                        if tag == 0x6ffffffb && (val & 0x08000000) != 0 {
                            has_pie_flag = true;
                        }
                    }
                }
            } else if p_type == 3 {
                // PT_INTERP
                let (p_offset, p_filesz) = if is_64 {
                    (
                        read_u64(buffer, ph_start + 8).unwrap_or(0) as usize,
                        read_u64(buffer, ph_start + 32).unwrap_or(0) as usize,
                    )
                } else {
                    (
                        read_u32(buffer, ph_start + 4).unwrap_or(0) as usize,
                        read_u32(buffer, ph_start + 16).unwrap_or(0) as usize,
                    )
                };
                if p_offset < buffer.len() {
                    let max_end = (p_offset + p_filesz).min(buffer.len());
                    let interp_bytes = &buffer[p_offset..max_end];
                    let null_pos = memchr::memchr(0, interp_bytes).unwrap_or(interp_bytes.len());
                    if let Ok(s) = std::str::from_utf8(&interp_bytes[..null_pos]) {
                        interpreter = Some(s.to_string());
                    }
                }
            } else if p_type == 4 {
                // PT_NOTE
                let (p_offset, p_filesz, p_align) = if is_64 {
                    (
                        read_u64(buffer, ph_start + 8).unwrap_or(0) as usize,
                        read_u64(buffer, ph_start + 32).unwrap_or(0) as usize,
                        read_u64(buffer, ph_start + 48).unwrap_or(4) as usize,
                    )
                } else {
                    (
                        read_u32(buffer, ph_start + 4).unwrap_or(0) as usize,
                        read_u32(buffer, ph_start + 16).unwrap_or(0) as usize,
                        read_u32(buffer, ph_start + 28).unwrap_or(4) as usize,
                    )
                };
                if p_filesz > 0 && p_filesz <= 65536 {
                    let mut note_data = Vec::new();
                    let note_slice: &[u8] = if p_offset + p_filesz <= buffer.len() {
                        &buffer[p_offset..p_offset + p_filesz]
                    } else if let Some(p) = path {
                        use std::io::{Read, Seek, SeekFrom};
                        if let Ok(mut f) = std::fs::File::open(p) {
                            if f.seek(SeekFrom::Start(p_offset as u64)).is_ok() {
                                note_data.resize(p_filesz, 0);
                                if f.read_exact(&mut note_data).is_ok() {
                                    &note_data[..]
                                } else {
                                    &[]
                                }
                            } else {
                                &[]
                            }
                        } else {
                            &[]
                        }
                    } else {
                        &[]
                    };
                    if !note_slice.is_empty() {
                        parse_notes(note_slice, is_lsb, p_align, &mut build_id, &mut os_version);
                        if os_version.is_none() && p_align != 4 {
                            parse_notes(note_slice, is_lsb, 4, &mut build_id, &mut os_version);
                        }
                    }
                }
            }
        }
    }

    // Section headers stripped status (check SHT_SYMTAB = 2) and SHT_NOTE = 7
    let (shoff, shentsize, shnum) = if is_64 {
        let shoff = read_u64(buffer, 40).unwrap_or(0) as usize;
        let shentsize = read_u16(buffer, 58).unwrap_or(0) as usize;
        let shnum = read_u16(buffer, 60).unwrap_or(0) as usize;
        (shoff, shentsize, shnum)
    } else {
        let shoff = read_u32(buffer, 32).unwrap_or(0) as usize;
        let shentsize = read_u16(buffer, 46).unwrap_or(0) as usize;
        let shnum = read_u16(buffer, 48).unwrap_or(0) as usize;
        (shoff, shentsize, shnum)
    };

    let mut has_symtab = false;
    let scan_shnum = shnum.min(config.params.elf_shnum);
    if shoff > 0 && shentsize >= 8 {
        let mut file_opt = path.and_then(|p| std::fs::File::open(p).ok());
        use std::io::{Read, Seek, SeekFrom};

        for i in 0..scan_shnum {
            let sh_start = shoff + i * shentsize;
            let mut sh_buf = [0u8; 64];
            let sh_slice: &[u8] = if sh_start + shentsize <= buffer.len() {
                &buffer[sh_start..sh_start + shentsize]
            } else if let Some(ref mut f) = file_opt {
                if f.seek(SeekFrom::Start(sh_start as u64)).is_ok()
                    && f.read_exact(&mut sh_buf[..shentsize.min(64)]).is_ok()
                {
                    &sh_buf[..shentsize.min(64)]
                } else {
                    continue;
                }
            } else {
                continue;
            };

            let sh_type = if sh_slice.len() >= 8 {
                read_u32(sh_slice, 4).unwrap_or(0)
            } else {
                0
            };

            if sh_type == 2 {
                has_symtab = true;
            } else if sh_type == 7 {
                // SHT_NOTE
                let (s_offset, s_size, s_align) = if is_64 {
                    if sh_slice.len() >= 56 {
                        (
                            read_u64(sh_slice, 24).unwrap_or(0) as usize,
                            read_u64(sh_slice, 32).unwrap_or(0) as usize,
                            read_u64(sh_slice, 48).unwrap_or(4) as usize,
                        )
                    } else {
                        (0, 0, 4)
                    }
                } else {
                    if sh_slice.len() >= 36 {
                        (
                            read_u32(sh_slice, 16).unwrap_or(0) as usize,
                            read_u32(sh_slice, 20).unwrap_or(0) as usize,
                            read_u32(sh_slice, 32).unwrap_or(4) as usize,
                        )
                    } else {
                        (0, 0, 4)
                    }
                };

                if s_size > 0 && s_size <= 65536 {
                    let mut note_data = Vec::new();
                    let note_slice: &[u8] = if s_offset + s_size <= buffer.len() {
                        &buffer[s_offset..s_offset + s_size]
                    } else if let Some(ref mut f) = file_opt {
                        if f.seek(SeekFrom::Start(s_offset as u64)).is_ok() {
                            note_data.resize(s_size, 0);
                            if f.read_exact(&mut note_data).is_ok() {
                                &note_data[..]
                            } else {
                                &[]
                            }
                        } else {
                            &[]
                        }
                    } else {
                        &[]
                    };

                    if !note_slice.is_empty() {
                        parse_notes(note_slice, is_lsb, s_align, &mut build_id, &mut os_version);
                        if os_version.is_none() && s_align != 4 {
                            parse_notes(note_slice, is_lsb, 4, &mut build_id, &mut os_version);
                        }
                    }
                }
            }
        }
    }

    let stripped_desc = if shnum == 0 {
        "no section header"
    } else if has_symtab {
        "not stripped"
    } else {
        "stripped"
    };

    let is_pie = interpreter.is_some() || has_pie_flag;
    let (type_desc, mime_type) = match e_type {
        1 => ("relocatable", "application/x-object"),
        2 => ("executable", "application/x-executable"),
        3 => {
            if is_pie {
                ("pie executable", "application/x-pie-executable")
            } else {
                ("shared object", "application/x-sharedlib")
            }
        }
        4 => ("core file", "application/x-coredump"),
        _ => ("unknown type", "application/x-executable"),
    };

    let mut desc = format!("ELF {class_desc} {data_desc} {type_desc}, {machine_desc}, version 1 ({osabi_desc})");

    if has_dynamic {
        if has_pie_flag && need_count == 0 {
            desc.push_str(", static-pie linked");
        } else {
            desc.push_str(", dynamically linked");
        }
    } else if e_type == 2 || e_type == 3 {
        desc.push_str(", statically linked");
    }

    if let Some(interp) = interpreter {
        desc.push_str(&format!(", interpreter {interp}"));
    }

    if let Some(bid) = build_id {
        desc.push_str(&format!(", BuildID[sha1]={bid}"));
    }

    if let Some(os) = os_version {
        desc.push_str(&format!(", for GNU/Linux {os}"));
    }

    desc.push_str(&format!(", {stripped_desc}"));

    Some(SpecializedResult {
        description: desc,
        mime_type: mime_type.to_string(),
        mime_encoding: "binary".to_string(),
        extensions: "???".to_string(),
        apple: "UNKNUNKN".to_string(),
    })
}

fn parse_notes(
    slice: &[u8],
    is_lsb: bool,
    align: usize,
    build_id: &mut Option<String>,
    os_version: &mut Option<String>,
) {
    let mut pos = 0;
    let align = if align < 4 { 4 } else { align };
    while pos + 12 <= slice.len() {
        let namesz = if is_lsb {
            u32::from_le_bytes([slice[pos], slice[pos + 1], slice[pos + 2], slice[pos + 3]]) as usize
        } else {
            u32::from_be_bytes([slice[pos], slice[pos + 1], slice[pos + 2], slice[pos + 3]]) as usize
        };
        let descsz = if is_lsb {
            u32::from_le_bytes([slice[pos + 4], slice[pos + 5], slice[pos + 6], slice[pos + 7]]) as usize
        } else {
            u32::from_be_bytes([slice[pos + 4], slice[pos + 5], slice[pos + 6], slice[pos + 7]]) as usize
        };
        let n_type = if is_lsb {
            u32::from_le_bytes([slice[pos + 8], slice[pos + 9], slice[pos + 10], slice[pos + 11]])
        } else {
            u32::from_be_bytes([slice[pos + 8], slice[pos + 9], slice[pos + 10], slice[pos + 11]])
        };
        pos += 12;

        let name_aligned = ((namesz + align - 1) / align) * align;
        let desc_aligned = ((descsz + align - 1) / align) * align;

        if pos + namesz > slice.len() {
            break;
        }

        let name = &slice[pos..pos + namesz];
        let desc_start = pos + name_aligned;
        if desc_start + descsz > slice.len() {
            break;
        }
        let desc = &slice[desc_start..desc_start + descsz];

        if name == b"GNU\0" || name == b"GNU" {
            if n_type == 3 && build_id.is_none() {
                // NT_GNU_BUILD_ID
                let hex: String = desc.iter().map(|b| format!("{b:02x}")).collect();
                *build_id = Some(hex);
            } else if n_type == 1 && descsz >= 16 && os_version.is_none() {
                // NT_GNU_ABI_TAG
                let major = if is_lsb {
                    u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]])
                } else {
                    u32::from_be_bytes([desc[4], desc[5], desc[6], desc[7]])
                };
                let minor = if is_lsb {
                    u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]])
                } else {
                    u32::from_be_bytes([desc[8], desc[9], desc[10], desc[11]])
                };
                let patch = if is_lsb {
                    u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]])
                } else {
                    u32::from_be_bytes([desc[12], desc[13], desc[14], desc[15]])
                };
                *os_version = Some(format!("{major}.{minor}.{patch}"));
            }
        }

        pos += name_aligned + desc_aligned;
    }
}
