// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumericType {
    Byte,
    Short(Endianness),
    Long(Endianness),
    Quad(Endianness),
    Date(Endianness),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicType {
    Numeric(NumericType),
    String { case_insensitive: bool },
    PString, // Pascal string (length prefixed)
    Search { max_length: usize },
    Regex { max_length: usize },
    Name(String),
    Use(String),
    Clear,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offset {
    Direct(usize),
    Relative(isize),
    Indirect {
        base: usize,
        type_size: usize,
        endian: Endianness,
        delta: isize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    LessThan,
    GreaterThan,
    BitwiseAnd,
    BitwiseAny,
    AlwaysTrue, // 'x'
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestValue {
    Unsigned(u64),
    Signed(i64),
    Bytes(Vec<u8>),
    Regex(String),
    Any,
}

#[derive(Debug, Clone)]
pub struct MagicRule {
    pub level: usize,
    pub offset: Offset,
    pub rule_type: MagicType,
    pub mask: Option<u64>,
    pub op: ComparisonOp,
    pub value: TestValue,
    pub message: String,
    pub mime_type: Option<String>,
    pub mime_encoding: Option<String>,
    pub extensions: Option<String>,
    pub apple: Option<String>,
    pub factor: i32,
    pub children: Vec<MagicRule>,
}

impl MagicRule {
    pub fn new(level: usize, offset: Offset, rule_type: MagicType, op: ComparisonOp, value: TestValue, message: String) -> Self {
        Self {
            level,
            offset,
            rule_type,
            mask: None,
            op,
            value,
            message,
            mime_type: None,
            mime_encoding: None,
            extensions: None,
            apple: None,
            factor: 0,
            children: Vec::new(),
        }
    }

    /// Compute apprentice strength for rule sorting (descending).
    pub fn strength(&self) -> usize {
        const MULT: usize = 10;
        let mut val: isize = 2 * (MULT as isize);

        let vallen = match &self.value {
            TestValue::Bytes(b) => b.len(),
            TestValue::Regex(s) => s.len(),
            _ => 0,
        };

        match &self.rule_type {
            MagicType::Default => return 0,
            MagicType::Numeric(n) => {
                let ts = match n {
                    NumericType::Byte => 1,
                    NumericType::Short(_) => 2,
                    NumericType::Long(_) | NumericType::Date(_) => 4,
                    NumericType::Quad(_) => 8,
                };
                val += (ts * MULT) as isize;
            }
            MagicType::String { .. } | MagicType::PString => {
                val += (vallen * MULT) as isize;
            }
            MagicType::Search { .. } => {
                if vallen > 0 {
                    val += (vallen * (MULT / vallen).max(1)) as isize;
                }
            }
            MagicType::Regex { .. } => {
                if vallen > 0 {
                    val += (vallen * (MULT / vallen).max(1)) as isize;
                }
            }
            _ => {}
        }

        match self.op {
            ComparisonOp::AlwaysTrue | ComparisonOp::NotEqual => val = 0,
            ComparisonOp::Equal => val += MULT as isize,
            ComparisonOp::LessThan | ComparisonOp::GreaterThan => val -= 2 * (MULT as isize),
            ComparisonOp::BitwiseAnd | ComparisonOp::BitwiseAny => val -= MULT as isize,
        }

        if self.factor != 0 {
            val += self.factor as isize;
        }

        if val <= 0 {
            val = 1;
        }
        if self.message.is_empty() {
            val += 1;
        }

        val.max(0) as usize
    }
}
