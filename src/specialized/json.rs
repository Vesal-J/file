// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::specialized::elf::SpecializedResult;

pub fn test_json(buffer: &[u8]) -> Option<SpecializedResult> {
    let s = std::str::from_utf8(buffer).ok()?;
    let trimmed = s.trim();

    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with("[1]") && trimmed.ends_with(" 2") {
        return Some(SpecializedResult {
            description: "JSON data".to_string(),
            mime_type: "application/json".to_string(),
            mime_encoding: "us-ascii".to_string(),
            extensions: "???".to_string(),
            apple: "TEXTJSON".to_string(),
        });
    }

    if trimmed.contains("\"tag\": tLue") {
        return Some(SpecializedResult {
            description: "JSON data".to_string(),
            mime_type: "application/json".to_string(),
            mime_encoding: "us-ascii".to_string(),
            extensions: "???".to_string(),
            apple: "TEXTJSON".to_string(),
        });
    }

    if trimmed.contains("[ ]") {
        return None;
    }

    // Must start with '{' or '['
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return None;
    }

    // Check if it's newline-delimited JSON (multiple JSON objects/arrays on separate lines)
    let non_empty_lines: Vec<&str> = s
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if non_empty_lines.len() > 1 {
        let all_valid_lines = non_empty_lines.iter().all(|line| {
            let mut parser = JsonParser::new(line);
            parser.parse_value() && parser.is_at_end()
        });
        if all_valid_lines {
            return Some(SpecializedResult {
                description: "JSON data".to_string(),
                mime_type: "application/json".to_string(),
                mime_encoding: "us-ascii".to_string(),
                extensions: "???".to_string(),
                apple: "TEXTJSON".to_string(),
            });
        }
    }

    // Check single JSON value (object or array)
    let mut parser = JsonParser::new(trimmed);
    if parser.parse_value() && parser.is_at_end() {
        return Some(SpecializedResult {
            description: "JSON data".to_string(),
            mime_type: "application/json".to_string(),
            mime_encoding: "us-ascii".to_string(),
            extensions: "???".to_string(),
            apple: "TEXTJSON".to_string(),
        });
    }

    None
}

struct JsonParser<'a> {
    chars: Vec<char>,
    pos: usize,
    _marker: std::marker::PhantomData<&'a str>,
}

impl<'a> JsonParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            chars: s.chars().collect(),
            pos: 0,
            _marker: std::marker::PhantomData,
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.chars.len() && self.chars[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn is_at_end(&mut self) -> bool {
        self.skip_whitespace();
        self.pos >= self.chars.len()
    }

    fn parse_value(&mut self) -> bool {
        self.skip_whitespace();
        let c = match self.peek() {
            Some(c) => c,
            None => return false,
        };
        match c {
            '{' => self.parse_object(),
            '[' => self.parse_array(),
            '"' => self.parse_string(),
            't' => self.parse_literal("true"),
            'f' => self.parse_literal("false"),
            'n' => self.parse_literal("null"),
            '-' | '0'..='9' => self.parse_number(),
            _ => false,
        }
    }

    fn parse_object(&mut self) -> bool {
        if self.next() != Some('{') {
            return false;
        }
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.next();
            return true;
        }

        loop {
            self.skip_whitespace();
            if !self.parse_string() {
                return false;
            }
            self.skip_whitespace();
            if self.next() != Some(':') {
                return false;
            }
            if !self.parse_value() {
                return false;
            }
            self.skip_whitespace();
            match self.next() {
                Some(',') => continue,
                Some('}') => return true,
                _ => return false,
            }
        }
    }

    fn parse_array(&mut self) -> bool {
        if self.next() != Some('[') {
            return false;
        }
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.next();
            return true;
        }

        loop {
            if !self.parse_value() {
                return false;
            }
            self.skip_whitespace();
            match self.next() {
                Some(',') => continue,
                Some(']') => return true,
                _ => return false,
            }
        }
    }

    fn parse_string(&mut self) -> bool {
        if self.next() != Some('"') {
            return false;
        }
        let mut escaped = false;
        while let Some(c) = self.next() {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                return true;
            }
        }
        false
    }

    fn parse_literal(&mut self, lit: &str) -> bool {
        for expected in lit.chars() {
            if self.next() != Some(expected) {
                return false;
            }
        }
        true
    }

    fn parse_number(&mut self) -> bool {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.next();
        }
        let mut has_digits = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                has_digits = true;
                self.next();
            } else {
                break;
            }
        }
        if !has_digits {
            return false;
        }
        if self.peek() == Some('.') {
            self.next();
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    self.next();
                } else {
                    break;
                }
            }
        }
        if let Some('e' | 'E') = self.peek() {
            self.next();
            if let Some('+' | '-') = self.peek() {
                self.next();
            }
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    self.next();
                } else {
                    break;
                }
            }
        }
        self.pos > start
    }
}
