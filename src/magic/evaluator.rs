// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::config::Config;
use crate::magic::ast::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicMatch {
    pub description: String,
    pub mime_type: Option<String>,
    pub mime_encoding: Option<String>,
    pub extensions: Option<String>,
    pub apple: Option<String>,
}

pub struct Evaluator<'a> {
    buffer: &'a [u8],
    #[allow(dead_code)]
    config: &'a Config,
    recursion_depth: usize,
}

impl<'a> Evaluator<'a> {
    pub fn new(buffer: &'a [u8], config: &'a Config) -> Self {
        Self {
            buffer,
            config,
            recursion_depth: 0,
        }
    }

    pub fn evaluate_rules(&mut self, rules: &[MagicRule]) -> Option<MagicMatch> {
        for rule in rules {
            if let Some(m) = self.evaluate_rule_tree(rule, 0) {
                return Some(m);
            }
        }
        None
    }

    /// Like `evaluate_rules` but collects ALL matching top-level rules for `-k` mode.
    pub fn evaluate_rules_keep_going(&mut self, rules: &[MagicRule]) -> Vec<MagicMatch> {
        let mut results = Vec::new();
        for rule in rules {
            if let Some(m) = self.evaluate_rule_tree(rule, 0) {
                // Only include rules that produce a non-empty description
                if !m.description.is_empty() {
                    results.push(m);
                }
            }
        }
        results
    }

    fn evaluate_rule_tree(&mut self, rule: &MagicRule, prev_end_offset: usize) -> Option<MagicMatch> {
        let (matched, match_end, val_opt) = self.test_rule(rule, prev_end_offset)?;
        if !matched {
            return None;
        }

        let mut desc = format_message(&rule.message, val_opt);
        let mut mime_type = rule.mime_type.clone();
        let mut mime_encoding = rule.mime_encoding.clone();
        let mut extensions = rule.extensions.clone();
        let mut apple = rule.apple.clone();

        // Recursively evaluate children
        for child in &rule.children {
            if let Some(child_match) = self.evaluate_child_tree(child, match_end) {
                if !child_match.description.is_empty() {
                    if !desc.is_empty() && !child_match.description.starts_with(',') && !child_match.description.starts_with(' ') {
                        desc.push(' ');
                    }
                    desc.push_str(&child_match.description);
                }
                if child_match.mime_type.is_some() {
                    mime_type = child_match.mime_type;
                }
                if child_match.mime_encoding.is_some() {
                    mime_encoding = child_match.mime_encoding;
                }
                if child_match.extensions.is_some() {
                    extensions = child_match.extensions;
                }
                if child_match.apple.is_some() {
                    apple = child_match.apple;
                }
            }
        }

        Some(MagicMatch {
            description: desc,
            mime_type,
            mime_encoding,
            extensions,
            apple,
        })
    }

    fn evaluate_child_tree(&mut self, rule: &MagicRule, prev_end_offset: usize) -> Option<MagicMatch> {
        if self.recursion_depth > 32 {
            return None;
        }
        self.recursion_depth += 1;
        let res = self.evaluate_rule_tree(rule, prev_end_offset);
        self.recursion_depth -= 1;
        res
    }

    fn test_rule(
        &self,
        rule: &MagicRule,
        prev_end_offset: usize,
    ) -> Option<(bool, usize, Option<MatchedValue>)> {
        let offset = self.resolve_offset(&rule.offset, prev_end_offset)?;

        match &rule.rule_type {
            MagicType::Numeric(num_type) => {
                let (val, len) = read_numeric(self.buffer, offset, num_type)?;
                let masked_val = if let Some(m) = rule.mask { val & m } else { val };

                let matched = match rule.op {
                    ComparisonOp::AlwaysTrue => true,
                    ComparisonOp::Equal => match rule.value {
                        TestValue::Unsigned(expected) => masked_val == expected,
                        TestValue::Signed(expected) => (masked_val as i64) == expected,
                        _ => false,
                    },
                    ComparisonOp::NotEqual => match rule.value {
                        TestValue::Unsigned(expected) => masked_val != expected,
                        _ => false,
                    },
                    ComparisonOp::LessThan => match rule.value {
                        TestValue::Unsigned(expected) => masked_val < expected,
                        _ => false,
                    },
                    ComparisonOp::GreaterThan => match rule.value {
                        TestValue::Unsigned(expected) => masked_val > expected,
                        _ => false,
                    },
                    ComparisonOp::BitwiseAnd => match rule.value {
                        TestValue::Unsigned(expected) => (masked_val & expected) == expected,
                        _ => false,
                    },
                    ComparisonOp::BitwiseAny => match rule.value {
                        TestValue::Unsigned(expected) => (masked_val & expected) != 0,
                        _ => false,
                    },
                };

                Some((matched, offset + len, Some(MatchedValue::Numeric(val))))
            }
            MagicType::String { case_insensitive } => {
                if let TestValue::Bytes(expected) = &rule.value {
                    let len = expected.len();
                    let slice = self.buffer.get(offset..offset + len)?;
                    let matched = if *case_insensitive {
                        slice.eq_ignore_ascii_case(expected)
                    } else {
                        slice == expected.as_slice()
                    };
                    Some((matched, offset + len, Some(MatchedValue::String(String::from_utf8_lossy(slice).to_string()))))
                } else if rule.op == ComparisonOp::AlwaysTrue {
                    Some((true, offset, None))
                } else {
                    None
                }
            }
            MagicType::PString => {
                let len = *self.buffer.get(offset)? as usize;
                let slice = self.buffer.get(offset + 1..offset + 1 + len)?;
                if let TestValue::Bytes(expected) = &rule.value {
                    let matched = slice == expected.as_slice();
                    Some((matched, offset + 1 + len, Some(MatchedValue::String(String::from_utf8_lossy(slice).to_string()))))
                } else {
                    Some((true, offset + 1 + len, Some(MatchedValue::String(String::from_utf8_lossy(slice).to_string()))))
                }
            }
            MagicType::Search { max_length } => {
                if let TestValue::Bytes(expected) = &rule.value {
                    let search_window = self.buffer.get(offset..(offset + max_length).min(self.buffer.len()))?;
                    if let Some(pos) = search_window.windows(expected.len()).position(|w| w == expected.as_slice()) {
                        Some((true, offset + pos + expected.len(), None))
                    } else {
                        Some((false, offset, None))
                    }
                } else {
                    None
                }
            }
            MagicType::Regex { max_length } => {
                if let TestValue::Regex(pattern) = &rule.value {
                    let search_window = self.buffer.get(offset..(offset + max_length).min(self.buffer.len()))?;
                    if let Ok(re) = regex::bytes::Regex::new(pattern) {
                        if let Some(mat) = re.find(search_window) {
                            Some((true, offset + mat.end(), None))
                        } else {
                            Some((false, offset, None))
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            MagicType::Clear => Some((true, offset, None)),
            MagicType::Default => Some((true, offset, None)),
            _ => None,
        }
    }

    fn resolve_offset(&self, offset: &Offset, prev_end_offset: usize) -> Option<usize> {
        match offset {
            Offset::Direct(n) => Some(*n),
            Offset::Relative(n) => {
                let target = (prev_end_offset as isize) + n;
                if target >= 0 {
                    Some(target as usize)
                } else {
                    None
                }
            }
            Offset::Indirect {
                base,
                type_size,
                endian,
                delta,
            } => {
                let slice = self.buffer.get(*base..*base + type_size)?;
                let ind_val = match (type_size, endian) {
                    (1, _) => slice[0] as usize,
                    (2, Endianness::Little) => u16::from_le_bytes([slice[0], slice[1]]) as usize,
                    (2, Endianness::Big) => u16::from_be_bytes([slice[0], slice[1]]) as usize,
                    (4, Endianness::Little) => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize,
                    (4, Endianness::Big) => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize,
                    _ => u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize,
                };
                let target = (ind_val as isize) + delta;
                if target >= 0 {
                    Some(target as usize)
                } else {
                    None
                }
            }
        }
    }
}

enum MatchedValue {
    Numeric(u64),
    String(String),
}

fn read_numeric(buffer: &[u8], offset: usize, num_type: &NumericType) -> Option<(u64, usize)> {
    match num_type {
        NumericType::Byte => {
            let b = *buffer.get(offset)?;
            Some((b as u64, 1))
        }
        NumericType::Short(endian) => {
            let slice = buffer.get(offset..offset + 2)?;
            let val = match endian {
                Endianness::Little => u16::from_le_bytes([slice[0], slice[1]]),
                Endianness::Big => u16::from_be_bytes([slice[0], slice[1]]),
                Endianness::Native => u16::from_ne_bytes([slice[0], slice[1]]),
            };
            Some((val as u64, 2))
        }
        NumericType::Long(endian) | NumericType::Date(endian) => {
            let slice = buffer.get(offset..offset + 4)?;
            let val = match endian {
                Endianness::Little => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
                Endianness::Big => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]),
                Endianness::Native => u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]),
            };
            Some((val as u64, 4))
        }
        NumericType::Quad(endian) => {
            let slice = buffer.get(offset..offset + 8)?;
            let val = match endian {
                Endianness::Little => u64::from_le_bytes([
                    slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
                ]),
                Endianness::Big => u64::from_be_bytes([
                    slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
                ]),
                Endianness::Native => u64::from_ne_bytes([
                    slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
                ]),
            };
            Some((val, 8))
        }
    }
}

fn format_message(msg: &str, val_opt: Option<MatchedValue>) -> String {
    if !msg.contains('%') {
        return msg.to_string();
    }

    if let Some(val) = val_opt {
        match val {
            MatchedValue::Numeric(n) => {
                if msg.contains("%d") {
                    msg.replace("%d", &n.to_string())
                } else if msg.contains("%u") {
                    msg.replace("%u", &n.to_string())
                } else if msg.contains("%x") {
                    msg.replace("%x", &format!("{n:x}"))
                } else if msg.contains("%X") {
                    msg.replace("%X", &format!("{n:X}"))
                } else {
                    msg.to_string()
                }
            }
            MatchedValue::String(s) => {
                if msg.contains("%s") {
                    msg.replace("%s", &s)
                } else {
                    msg.to_string()
                }
            }
        }
    } else {
        msg.to_string()
    }
}
