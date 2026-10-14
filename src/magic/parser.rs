// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::magic::ast::*;

pub fn parse_magic_file(content: &str) -> Vec<MagicRule> {
    let mut flat_rules: Vec<MagicRule> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Modifiers for the last rule
        if trimmed.starts_with("!:") {
            if let Some(last) = flat_rules.last_mut() {
                if let Some(mime) = trimmed.strip_prefix("!:mime") {
                    last.mime_type = Some(mime.trim().to_string());
                } else if let Some(ext) = trimmed.strip_prefix("!:ext") {
                    last.extensions = Some(ext.trim().to_string());
                } else if let Some(apple) = trimmed.strip_prefix("!:apple") {
                    last.apple = Some(apple.trim().to_string());
                } else if let Some(strength) = trimmed.strip_prefix("!:strength") {
                    if let Ok(val) = strength.trim().parse::<i32>() {
                        last.factor = val;
                    }
                }
            }
            continue;
        }

        if let Some(rule) = parse_line(line) {
            flat_rules.push(rule);
        }
    }

    // Build hierarchy tree from flat rules
    build_hierarchy(flat_rules)
}

fn parse_line(line: &str) -> Option<MagicRule> {
    let mut chars = line.trim_start();

    // 1. Level: count leading '>'
    let mut level = 0;
    while chars.starts_with('>') {
        level += 1;
        chars = &chars[1..];
    }
    chars = chars.trim_start();

    // Split into tokens: offset, type, value, message
    let parts: Vec<&str> = chars.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let offset_str = parts[0];
    let type_str = parts[1];

    let offset = parse_offset(offset_str)?;
    let (rule_type, mask) = parse_type(type_str)?;

    let (op, value, message_start_idx) = if parts.len() > 2 {
        let (op, val) = parse_op_and_val(parts[2], &rule_type);
        (op, val, 3)
    } else {
        (ComparisonOp::AlwaysTrue, TestValue::Any, 2)
    };

    let message = if parts.len() > message_start_idx {
        parts[message_start_idx..].join(" ")
    } else {
        String::new()
    };

    let mut rule = MagicRule::new(level, offset, rule_type, op, value, message);
    rule.mask = mask;
    Some(rule)
}

fn parse_offset(s: &str) -> Option<Offset> {
    if let Some(rel) = s.strip_prefix('&') {
        let val = parse_num_isize(rel)?;
        return Some(Offset::Relative(val));
    }
    if s.starts_with('(') && s.ends_with(')') {
        // Indirect offset: e.g. (0x3c.l) or (4.s)
        let inner = &s[1..s.len() - 1];
        let (base_str, spec) = inner.split_once('.')?;
        let base = parse_num_usize(base_str)?;
        let (type_size, endian) = match spec.chars().next()? {
            'b' | 'B' => (1, Endianness::Native),
            's' => (2, Endianness::Little),
            'S' => (2, Endianness::Big),
            'l' => (4, Endianness::Little),
            'L' => (4, Endianness::Big),
            'q' => (8, Endianness::Little),
            'Q' => (8, Endianness::Big),
            _ => (4, Endianness::Native),
        };
        return Some(Offset::Indirect {
            base,
            type_size,
            endian,
            delta: 0,
        });
    }

    let val = parse_num_usize(s)?;
    Some(Offset::Direct(val))
}

fn parse_type(s: &str) -> Option<(MagicType, Option<u64>)> {
    let (base_type, mask) = if let Some((t, m)) = s.split_once('&') {
        (t, parse_num_u64(m))
    } else {
        (s, None)
    };

    let magic_type = match base_type.to_ascii_lowercase().as_str() {
        "byte" => MagicType::Numeric(NumericType::Byte),
        "short" => MagicType::Numeric(NumericType::Short(Endianness::Native)),
        "leshort" => MagicType::Numeric(NumericType::Short(Endianness::Little)),
        "beshort" => MagicType::Numeric(NumericType::Short(Endianness::Big)),
        "long" => MagicType::Numeric(NumericType::Long(Endianness::Native)),
        "lelong" => MagicType::Numeric(NumericType::Long(Endianness::Little)),
        "belong" => MagicType::Numeric(NumericType::Long(Endianness::Big)),
        "quad" => MagicType::Numeric(NumericType::Quad(Endianness::Native)),
        "lequad" => MagicType::Numeric(NumericType::Quad(Endianness::Little)),
        "bequad" => MagicType::Numeric(NumericType::Quad(Endianness::Big)),
        "date" => MagicType::Numeric(NumericType::Date(Endianness::Native)),
        "ledate" => MagicType::Numeric(NumericType::Date(Endianness::Little)),
        "bedate" => MagicType::Numeric(NumericType::Date(Endianness::Big)),
        "string" => MagicType::String { case_insensitive: false },
        "string/c" => MagicType::String { case_insensitive: true },
        "pstring" => MagicType::PString,
        "search" => MagicType::Search { max_length: 8192 },
        "regex" => MagicType::Regex { max_length: 8192 },
        "clear" => MagicType::Clear,
        "default" => MagicType::Default,
        _ => MagicType::String { case_insensitive: false },
    };

    Some((magic_type, mask))
}

fn parse_op_and_val(s: &str, rtype: &MagicType) -> (ComparisonOp, TestValue) {
    if s == "x" {
        return (ComparisonOp::AlwaysTrue, TestValue::Any);
    }

    let (op, val_str) = if let Some(rest) = s.strip_prefix('=') {
        (ComparisonOp::Equal, rest)
    } else if let Some(rest) = s.strip_prefix('!') {
        (ComparisonOp::NotEqual, rest)
    } else if let Some(rest) = s.strip_prefix('<') {
        (ComparisonOp::LessThan, rest)
    } else if let Some(rest) = s.strip_prefix('>') {
        (ComparisonOp::GreaterThan, rest)
    } else if let Some(rest) = s.strip_prefix('&') {
        (ComparisonOp::BitwiseAnd, rest)
    } else {
        (ComparisonOp::Equal, s)
    };

    match rtype {
        MagicType::Numeric(_) => {
            if let Some(n) = parse_num_u64(val_str) {
                (op, TestValue::Unsigned(n))
            } else {
                (op, TestValue::Unsigned(0))
            }
        }
        MagicType::String { .. } | MagicType::PString | MagicType::Search { .. } => {
            let bytes = unescape_string(val_str);
            (op, TestValue::Bytes(bytes))
        }
        MagicType::Regex { .. } => (op, TestValue::Regex(val_str.to_string())),
        _ => (op, TestValue::Any),
    }
}

fn unescape_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 1;
            match bytes[i] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'\\' => out.push(b'\\'),
                b'0'..=b'7' => {
                    // Octal escape
                    let mut val = (bytes[i] - b'0') as u8;
                    if i + 1 < bytes.len() && (b'0'..=b'7').contains(&bytes[i + 1]) {
                        i += 1;
                        val = val * 8 + (bytes[i] - b'0');
                        if i + 1 < bytes.len() && (b'0'..=b'7').contains(&bytes[i + 1]) {
                            i += 1;
                            val = val * 8 + (bytes[i] - b'0');
                        }
                    }
                    out.push(val);
                }
                b'x' => {
                    // Hex escape \xNN
                    if i + 2 < bytes.len() {
                        if let Ok(val) = u8::from_str_radix(
                            std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                            16,
                        ) {
                            out.push(val);
                            i += 2;
                        }
                    }
                }
                other => out.push(other),
            }
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    out
}

fn parse_num_usize(s: &str) -> Option<usize> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else if let Some(oct) = s.strip_prefix('0') {
        if oct.is_empty() {
            Some(0)
        } else {
            usize::from_str_radix(oct, 8).ok()
        }
    } else {
        s.parse::<usize>().ok()
    }
}

fn parse_num_isize(s: &str) -> Option<isize> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        isize::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<isize>().ok()
    }
}

fn parse_num_u64(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(oct) = s.strip_prefix('0') {
        if oct.is_empty() {
            Some(0)
        } else {
            u64::from_str_radix(oct, 8).ok()
        }
    } else {
        s.parse::<u64>().ok()
    }
}

fn build_hierarchy(rules: Vec<MagicRule>) -> Vec<MagicRule> {
    let mut root_rules: Vec<MagicRule> = Vec::new();
    let mut stack: Vec<MagicRule> = Vec::new();

    for rule in rules {
        while let Some(top) = stack.last() {
            if rule.level <= top.level {
                let finished = stack.pop().unwrap();
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(finished);
                } else {
                    root_rules.push(finished);
                }
            } else {
                break;
            }
        }
        stack.push(rule);
    }

    while let Some(finished) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(finished);
        } else {
            root_rules.push(finished);
        }
    }

    root_rules
}
