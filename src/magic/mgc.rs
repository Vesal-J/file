//! Reader for the compiled `magic.mgc` database layout used by file(1).
//!
//! The record layouts below are the upstream libmagic versions 16-18 and 20-21.
//! Unknown rule types and rule features that the Rust evaluator cannot model
//! are retained as nonmatching placeholder rules so continuation trees remain
//! attached to the correct parents.

use super::ast::{ComparisonOp, Endianness, MagicRule, MagicType, NumericType, Offset, TestValue};
use super::parser;
use std::io;

const HEADER_LEN: usize = 16;
const V16_RECORD_LEN: usize = 376;
const V21_RECORD_LEN: usize = 432;
const FILE_MAX_STRING: usize = 128;

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn u16(self, bytes: &[u8]) -> u16 {
        let value = [bytes[0], bytes[1]];
        match self {
            Self::Little => u16::from_le_bytes(value),
            Self::Big => u16::from_be_bytes(value),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Little => u32::from_le_bytes(value),
            Self::Big => u32::from_be_bytes(value),
        }
    }

    fn u64(self, bytes: &[u8]) -> u64 {
        let mut raw = [0; 8];
        let len = bytes.len().min(raw.len());
        raw[..len].copy_from_slice(&bytes[..len]);
        match self {
            Self::Little => u64::from_le_bytes(raw),
            Self::Big => u64::from_be_bytes(raw),
        }
    }
}

/// Decode a compiled database's content (set zero) into the Rust rule tree.
pub(super) fn parse(bytes: &[u8]) -> io::Result<Vec<MagicRule>> {
    if bytes.len() < HEADER_LEN {
        return Err(invalid(
            "compiled magic database is shorter than its header",
        ));
    }

    let order = match bytes[..4] {
        [0x1c, 0x04, 0x1e, 0xf1] => ByteOrder::Little,
        [0xf1, 0x1e, 0x04, 0x1c] => ByteOrder::Big,
        _ => return Err(invalid("bad compiled magic database signature")),
    };
    let version = order.u32(&bytes[4..8]);
    let (record_len, layout) = match version {
        16..=18 => (V16_RECORD_LEN, Layout::V16),
        20..=21 => (V21_RECORD_LEN, Layout::V21),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "unsupported compiled magic database version {other}; supported versions are 16-18 and 20-21"
                ),
            ));
        }
    };

    let content_count = order.u32(&bytes[8..12]) as usize;
    let name_count = order.u32(&bytes[12..16]) as usize;
    let total_count = content_count
        .checked_add(name_count)
        .ok_or_else(|| invalid("compiled magic database entry count overflows"))?;
    let expected_len = total_count
        .checked_mul(record_len)
        .and_then(|size| HEADER_LEN.checked_add(size))
        .ok_or_else(|| invalid("compiled magic database size overflows"))?;
    if expected_len != bytes.len() {
        return Err(invalid("compiled magic database has an inconsistent size"));
    }

    let mut rules = Vec::with_capacity(content_count);
    for index in 0..content_count {
        let start = HEADER_LEN + index * record_len;
        let record = &bytes[start..start + record_len];
        rules.push(parse_record(record, order, layout)?);
    }
    Ok(parser::build_hierarchy(rules))
}

#[derive(Clone, Copy)]
enum Layout {
    V16,
    V21,
}

fn parse_record(record: &[u8], order: ByteOrder, layout: Layout) -> io::Result<MagicRule> {
    let (flag, level, factor) = match layout {
        Layout::V16 => (
            record[2] as u16,
            order.u16(&record[0..2]) as usize,
            record[3],
        ),
        Layout::V21 => (order.u16(&record[0..2]), record[2] as usize, record[3]),
    };
    let relation = record[4];
    let value_len = (record[5] as usize).min(FILE_MAX_STRING);
    let type_code = record[6];
    let offset_value = order.u32(&record[12..16]) as i32;
    let indirect_type = record[7];
    let indirect_offset = order.u32(&record[16..20]) as i32;
    let value_bytes = &record[32..32 + FILE_MAX_STRING];
    let string_range = order.u32(&record[24..28]) as usize;
    let string_flags = order.u32(&record[28..32]);

    let (mut rule_type, mut offset, is_string) = match type_for_code(type_code, layout) {
        Some((ty, string)) => (
            ty,
            offset_for_record(flag, offset_value, indirect_type, indirect_offset)
                .unwrap_or(Offset::Direct(0)),
            string,
        ),
        None => (MagicType::Name(String::new()), Offset::Direct(0), false),
    };
    if offset_for_record(flag, offset_value, indirect_type, indirect_offset).is_none() {
        rule_type = MagicType::Name(String::new());
        offset = Offset::Direct(0);
    }

    let (op, mut value) =
        relation_and_value(relation, &rule_type, &value_bytes[..value_len], order);
    if !is_string {
        value = match &rule_type {
            MagicType::Numeric(_) => TestValue::Unsigned(order.u64(value_bytes)),
            _ => TestValue::Any,
        };
    }
    let mut rule = MagicRule::new(
        level,
        offset,
        rule_type,
        op,
        value,
        field_string(record, 160, 64),
    );
    rule.factor = factor as i32;

    let raw_mask = order.u64(&record[24..32]);
    if !is_string && raw_mask != 0 {
        rule.mask = Some(raw_mask);
    }
    if is_string {
        if let MagicType::Search { max_length } = &mut rule.rule_type {
            *max_length = string_range.max(1);
        }
        if let MagicType::Regex { max_length } = &mut rule.rule_type {
            *max_length = string_range.max(1);
        }
        if string_flags & ((1 << 2) | (1 << 3)) != 0 {
            if let MagicType::String { case_insensitive } = &mut rule.rule_type {
                *case_insensitive = true;
            }
        }
    }

    let mime_type = field_string(record, 224, 80);
    if !mime_type.is_empty() {
        rule.mime_type = Some(mime_type);
    }
    let apple = field_string(record, 304, 8);
    if !apple.is_empty() {
        rule.apple = Some(apple);
    }
    let ext_len = match layout {
        Layout::V16 => 64,
        Layout::V21 => 120,
    };
    let extensions = field_string(record, 312, ext_len);
    if !extensions.is_empty() {
        rule.extensions = Some(extensions);
    }
    Ok(rule)
}

fn offset_for_record(flag: u16, offset: i32, indirect_type: u8, delta: i32) -> Option<Offset> {
    const INDIR: u16 = 0x01;
    const OFFADD: u16 = 0x02;
    const OFFNEGATIVE: u16 = 0x80;
    if flag & OFFNEGATIVE != 0 {
        return None;
    }
    if flag & INDIR != 0 {
        let (type_size, endian) = match indirect_type {
            1 => (1, Endianness::Native),
            2 => (2, Endianness::Native),
            4 => (4, Endianness::Native),
            7 => (2, Endianness::Big),
            8 => (4, Endianness::Big),
            10 => (2, Endianness::Little),
            11 => (4, Endianness::Little),
            _ => return None,
        };
        let base = usize::try_from(offset).ok()?;
        return Some(Offset::Indirect {
            base,
            type_size,
            endian,
            delta: delta as isize,
        });
    }
    if flag & OFFADD != 0 {
        Some(Offset::Relative(offset as isize))
    } else {
        Some(Offset::Direct(usize::try_from(offset).ok()?))
    }
}

fn type_for_code(code: u8, layout: Layout) -> Option<(MagicType, bool)> {
    use Endianness::{Big, Little, Native};
    use MagicType::{Numeric, Regex, Search, String};
    use NumericType::{Date, Long, Quad, Short};
    let mapped = match code {
        1 => (Numeric(NumericType::Byte), false),
        2 => (Numeric(Short(Native)), false),
        3 => (MagicType::Default, false),
        4 => (Numeric(Long(Native)), false),
        5 => (
            String {
                case_insensitive: false,
            },
            true,
        ),
        6 => (Numeric(Date(Native)), false),
        7 => (Numeric(Short(Big)), false),
        8 => (Numeric(Long(Big)), false),
        9 => (Numeric(Date(Big)), false),
        10 => (Numeric(Short(Little)), false),
        11 => (Numeric(Long(Little)), false),
        12 => (Numeric(Date(Little)), false),
        13 => (MagicType::PString, true),
        14 => (Numeric(Date(Native)), false),
        15 => (Numeric(Date(Big)), false),
        16 => (Numeric(Date(Little)), false),
        17 => (Regex { max_length: 8192 }, true),
        20 => (Search { max_length: 8192 }, true),
        21 => (Numeric(Date(Native)), false),
        22 => (Numeric(Date(Little)), false),
        23 => (Numeric(Long(Native)), false),
        24 => (Numeric(Quad(Native)), false),
        25 => (Numeric(Quad(Little)), false),
        26 => (Numeric(Quad(Big)), false),
        27 => (Numeric(Date(Native)), false),
        28 => (Numeric(Date(Little)), false),
        29 => (Numeric(Date(Big)), false),
        30 => (Numeric(Date(Native)), false),
        31 => (Numeric(Date(Little)), false),
        32 => (Numeric(Date(Big)), false),
        47 => (MagicType::Clear, false),
        _ => return None,
    };
    if matches!(code, 50 | 51 | 52 | 53 | 54) && matches!(layout, Layout::V21) {
        return None;
    }
    Some(mapped)
}

fn relation_and_value(
    relation: u8,
    rule_type: &MagicType,
    bytes: &[u8],
    order: ByteOrder,
) -> (ComparisonOp, TestValue) {
    let op = match relation {
        0 | b'=' => ComparisonOp::Equal,
        b'!' => ComparisonOp::NotEqual,
        b'<' => ComparisonOp::LessThan,
        b'>' => ComparisonOp::GreaterThan,
        b'&' => ComparisonOp::BitwiseAnd,
        b'^' => ComparisonOp::BitwiseAny,
        b'x' => ComparisonOp::AlwaysTrue,
        _ => ComparisonOp::Equal,
    };
    let value = match rule_type {
        MagicType::Numeric(_) => TestValue::Unsigned(order.u64(bytes)),
        MagicType::Regex { .. } => TestValue::Regex(String::from_utf8_lossy(bytes).into_owned()),
        MagicType::String { .. } | MagicType::PString | MagicType::Search { .. } => {
            TestValue::Bytes(bytes.to_vec())
        }
        _ => TestValue::Any,
    };
    (op, value)
}

fn field_string(record: &[u8], offset: usize, len: usize) -> String {
    let bytes = &record[offset..offset + len];
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
