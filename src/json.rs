// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        src/json.rs
// Role:          Zero-Dependency Clean-Room JSON Lexer, Parser & Serializer
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

//! Zero-dependency clean-room JSON lexer, recursive descent parser, and serializer.

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Number(n) if *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => {
                for (k, v) in entries {
                    if k == key {
                        return Some(v);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let chars: Vec<char> = input.chars().collect();
        let mut idx = 0;
        skip_whitespace(&chars, &mut idx);
        let val = parse_value(&chars, &mut idx)?;
        skip_whitespace(&chars, &mut idx);
        if idx < chars.len() {
            return Err(format!(
                "Unexpected trailing characters at position {}",
                idx
            ));
        }
        Ok(val)
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        serialize_val(self, 0, &mut out);
        out
    }
}

fn skip_whitespace(chars: &[char], idx: &mut usize) {
    while *idx < chars.len() && chars[*idx].is_whitespace() {
        *idx += 1;
    }
}

fn parse_value(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    skip_whitespace(chars, idx);
    if *idx >= chars.len() {
        return Err("Unexpected end of JSON input".to_string());
    }

    match chars[*idx] {
        'n' => parse_null(chars, idx),
        't' | 'f' => parse_bool(chars, idx),
        '"' => parse_string(chars, idx).map(JsonValue::String),
        '[' => parse_array(chars, idx),
        '{' => parse_object(chars, idx),
        '-' | '0'..='9' => parse_number(chars, idx),
        c => Err(format!("Unexpected character '{}' at position {}", c, idx)),
    }
}

fn parse_null(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx + 4 <= chars.len() && chars[*idx..*idx + 4] == ['n', 'u', 'l', 'l'] {
        *idx += 4;
        Ok(JsonValue::Null)
    } else {
        Err(format!("Invalid null literal at position {}", idx))
    }
}

fn parse_bool(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx + 4 <= chars.len() && chars[*idx..*idx + 4] == ['t', 'r', 'u', 'e'] {
        *idx += 4;
        Ok(JsonValue::Bool(true))
    } else if *idx + 5 <= chars.len() && chars[*idx..*idx + 5] == ['f', 'a', 'l', 's', 'e'] {
        *idx += 5;
        Ok(JsonValue::Bool(false))
    } else {
        Err(format!("Invalid boolean literal at position {}", idx))
    }
}

fn parse_string(chars: &[char], idx: &mut usize) -> Result<String, String> {
    *idx += 1; // Skip opening quote
    let mut s = String::new();
    while *idx < chars.len() {
        match chars[*idx] {
            '"' => {
                *idx += 1;
                return Ok(s);
            }
            '\\' => {
                *idx += 1;
                if *idx >= chars.len() {
                    return Err("Unterminated escape sequence".to_string());
                }
                match chars[*idx] {
                    '"' => s.push('"'),
                    '\\' => s.push('\\'),
                    '/' => s.push('/'),
                    'b' => s.push('\x08'),
                    'f' => s.push('\x0C'),
                    'n' => s.push('\n'),
                    'r' => s.push('\r'),
                    't' => s.push('\t'),
                    'u' => {
                        *idx += 1;
                        if *idx + 4 > chars.len() {
                            return Err("Incomplete unicode escape".to_string());
                        }
                        let hex: String = chars[*idx..*idx + 4].iter().collect();
                        *idx += 3;
                        let cp = u32::from_str_radix(&hex, 16)
                            .map_err(|e| format!("Invalid unicode escape: {}", e))?;
                        if let Some(ch) = char::from_u32(cp) {
                            s.push(ch);
                        } else {
                            s.push('\u{FFFD}');
                        }
                    }
                    c => return Err(format!("Invalid escape character '{}'", c)),
                }
                *idx += 1;
            }
            c => {
                s.push(c);
                *idx += 1;
            }
        }
    }
    Err("Unterminated string literal".to_string())
}

fn parse_number(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    let start = *idx;
    if *idx < chars.len() && chars[*idx] == '-' {
        *idx += 1;
    }
    while *idx < chars.len() && chars[*idx].is_ascii_digit() {
        *idx += 1;
    }
    if *idx < chars.len() && chars[*idx] == '.' {
        *idx += 1;
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }
    if *idx < chars.len() && (chars[*idx] == 'e' || chars[*idx] == 'E') {
        *idx += 1;
        if *idx < chars.len() && (chars[*idx] == '+' || chars[*idx] == '-') {
            *idx += 1;
        }
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }

    let num_str: String = chars[start..*idx].iter().collect();
    let num: f64 = num_str
        .parse()
        .map_err(|e| format!("Invalid number '{}': {}", num_str, e))?;
    Ok(JsonValue::Number(num))
}

fn parse_array(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    *idx += 1; // Skip '['
    skip_whitespace(chars, idx);
    let mut arr = Vec::new();

    if *idx < chars.len() && chars[*idx] == ']' {
        *idx += 1;
        return Ok(JsonValue::Array(arr));
    }

    loop {
        skip_whitespace(chars, idx);
        let val = parse_value(chars, idx)?;
        arr.push(val);
        skip_whitespace(chars, idx);

        if *idx >= chars.len() {
            return Err("Unterminated array literal".to_string());
        }

        match chars[*idx] {
            ',' => {
                *idx += 1;
            }
            ']' => {
                *idx += 1;
                return Ok(JsonValue::Array(arr));
            }
            c => return Err(format!("Expected ',' or ']' in array, got '{}'", c)),
        }
    }
}

fn parse_object(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    *idx += 1; // Skip '{'
    skip_whitespace(chars, idx);
    let mut obj = Vec::new();

    if *idx < chars.len() && chars[*idx] == '}' {
        *idx += 1;
        return Ok(JsonValue::Object(obj));
    }

    loop {
        skip_whitespace(chars, idx);
        if *idx >= chars.len() || chars[*idx] != '"' {
            return Err("Expected string key in object".to_string());
        }
        let key = parse_string(chars, idx)?;
        skip_whitespace(chars, idx);

        if *idx >= chars.len() || chars[*idx] != ':' {
            return Err("Expected ':' after object key".to_string());
        }
        *idx += 1; // Skip ':'

        skip_whitespace(chars, idx);
        let val = parse_value(chars, idx)?;
        obj.push((key, val));
        skip_whitespace(chars, idx);

        if *idx >= chars.len() {
            return Err("Unterminated object literal".to_string());
        }

        match chars[*idx] {
            ',' => {
                *idx += 1;
            }
            '}' => {
                *idx += 1;
                return Ok(JsonValue::Object(obj));
            }
            c => return Err(format!("Expected ',' or '}}' in object, got '{}'", c)),
        }
    }
}

fn serialize_val(val: &JsonValue, indent: usize, out: &mut String) {
    match val {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                out.push_str(&format!("{:.0}", n));
            } else {
                out.push_str(&format!("{}", n));
            }
        }
        JsonValue::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    ch => out.push(ch),
                }
            }
            out.push('"');
        }
        JsonValue::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, elem) in arr.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                serialize_val(elem, indent + 2, out);
                if i + 1 < arr.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        JsonValue::Object(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (k, v)) in entries.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push('"');
                out.push_str(k);
                out.push_str("\": ");
                serialize_val(v, indent + 2, out);
                if i + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
    }
}
