// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        src/dbc_decoder.rs
// Role:          DBC Parser, Intel/Motorola Bit Extractor & Bosch CAN CRC-15
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

//! DBC database definitions, SocketCAN frame abstractions, and bitfield extraction.

use std::collections::HashMap;

/// Bosch CAN 2.0 CRC-15 Generator Polynomial (0x4599)
pub const CAN_CRC15_POLYNOMIAL: u16 = 0x4599;

/// Standard SocketCAN / CAN-FD Frame Representation
#[derive(Debug, Clone, PartialEq)]
pub struct CanFrame {
    pub id: u32,
    pub is_extended: bool,
    pub dlc: usize,
    pub data: Vec<u8>,
    pub timestamp: f64,
    pub interface: String,
}

impl CanFrame {
    pub fn new(
        id: u32,
        is_extended: bool,
        data: Vec<u8>,
        timestamp: f64,
        interface: String,
    ) -> Self {
        let dlc = data.len();
        Self {
            id,
            is_extended,
            dlc,
            data,
            timestamp,
            interface,
        }
    }

    /// Parse candump log line.
    /// Supports:
    ///   "(1700000000.010000) can0 123#DEADBEEF"
    ///   "can0 123#DEADBEEF"
    ///   "123#DEADBEEF"
    ///   "(1700000000.010000) can0 18DAF110#0210010000000000"
    pub fn parse_candump_line(line: &str) -> Result<Self, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Err("Empty or comment line".to_string());
        }

        let mut timestamp = 0.0;
        let mut iface = "can0".to_string();
        let frame_part: &str;

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            return Err("No tokens found in line".to_string());
        }

        if tokens[0].starts_with('(') && tokens[0].ends_with(')') {
            let ts_str = &tokens[0][1..tokens[0].len() - 1];
            timestamp = ts_str
                .parse::<f64>()
                .map_err(|e| format!("Invalid timestamp '{}': {}", ts_str, e))?;
            if tokens.len() >= 3 {
                iface = tokens[1].to_string();
                frame_part = tokens[2];
            } else if tokens.len() == 2 {
                frame_part = tokens[1];
            } else {
                return Err(format!("Malformed candump line '{}'", trimmed));
            }
        } else if tokens.len() >= 2 && tokens[0].contains("can") {
            iface = tokens[0].to_string();
            frame_part = tokens[1];
        } else {
            frame_part = tokens[0];
        }

        let parts: Vec<&str> = frame_part.split('#').collect();
        if parts.len() != 2 && parts.len() != 3 {
            return Err(format!("Invalid CAN frame format '{}'", frame_part));
        }

        let id_str = parts[0];
        let data_str = parts[parts.len() - 1];

        let id = u32::from_str_radix(id_str, 16)
            .map_err(|e| format!("Invalid hex ID '{}': {}", id_str, e))?;
        let is_extended = id > 0x7FF || id_str.len() > 3;

        let data = hex_to_bytes(data_str)?;

        Ok(CanFrame::new(id, is_extended, data, timestamp, iface))
    }
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim();
    #[allow(clippy::manual_is_multiple_of)]
    if clean.len() % 2 != 0 {
        return Err(format!("Hex string length must be even: '{}'", clean));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let b = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| format!("Invalid hex byte '{}': {}", &clean[i..i + 2], e))?;
        bytes.push(b);
    }
    Ok(bytes)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02X}", b));
    }
    out
}

/// Compute Bosch CAN 2.0 15-bit CRC over given data bytes
pub fn compute_can_crc15(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        for bit_idx in (0..8).rev() {
            let bit = (byte >> bit_idx) & 1;
            let crc_next = ((crc >> 14) & 1) ^ (bit as u16);
            crc = (crc << 1) & 0x7FFF;
            if crc_next != 0 {
                crc ^= CAN_CRC15_POLYNOMIAL;
            }
        }
    }
    crc
}

/// Endianness byte order definition in DBC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    MotorolaBigEndian, // '0' in DBC
    IntelLittleEndian, // '1' in DBC
}

/// Value sign definition in DBC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    Unsigned, // '+' in DBC
    Signed,   // '-' in DBC
}

/// Signal specification in DBC
#[derive(Debug, Clone, PartialEq)]
pub struct SignalDef {
    pub name: String,
    pub start_bit: usize,
    pub bit_length: usize,
    pub byte_order: ByteOrder,
    pub value_type: ValueType,
    pub scale: f64,
    pub offset: f64,
    pub min: f64,
    pub max: f64,
    pub unit: String,
    pub receivers: Vec<String>,
}

impl SignalDef {
    /// Extract raw integer from payload bytes
    pub fn extract_raw(&self, payload: &[u8]) -> Result<i64, String> {
        if self.bit_length == 0 || self.bit_length > 64 {
            return Err(format!("Invalid signal bit length {}", self.bit_length));
        }

        match self.byte_order {
            ByteOrder::IntelLittleEndian => {
                let mut raw_u64: u64 = 0;
                for b in 0..self.bit_length {
                    let global_bit = self.start_bit + b;
                    let byte_idx = global_bit / 8;
                    let bit_in_byte = global_bit % 8;

                    if byte_idx >= payload.len() {
                        return Err(format!(
                            "Signal '{}' out of payload bounds: bit {} requires byte {} but payload len is {}",
                            self.name, global_bit, byte_idx, payload.len()
                        ));
                    }

                    let bit_val = ((payload[byte_idx] >> bit_in_byte) & 1) as u64;
                    raw_u64 |= bit_val << b;
                }

                if self.value_type == ValueType::Signed {
                    let sign_bit = (raw_u64 >> (self.bit_length - 1)) & 1;
                    if sign_bit == 1 {
                        let mask = !0u64 << self.bit_length;
                        Ok((raw_u64 | mask) as i64)
                    } else {
                        Ok(raw_u64 as i64)
                    }
                } else {
                    Ok(raw_u64 as i64)
                }
            }
            ByteOrder::MotorolaBigEndian => {
                let mut raw_u64: u64 = 0;
                let mut curr_byte = self.start_bit / 8;
                let mut curr_bit = (self.start_bit % 8) as i32;

                for b in 0..self.bit_length {
                    if curr_byte >= payload.len() {
                        return Err(format!(
                            "Signal '{}' out of payload bounds: step {} requires byte {} but payload len is {}",
                            self.name, b, curr_byte, payload.len()
                        ));
                    }

                    let bit_val = ((payload[curr_byte] >> curr_bit) & 1) as u64;
                    let weight_shift = self.bit_length - 1 - b;
                    raw_u64 |= bit_val << weight_shift;

                    if curr_bit == 0 {
                        curr_byte += 1;
                        curr_bit = 7;
                    } else {
                        curr_bit -= 1;
                    }
                }

                if self.value_type == ValueType::Signed {
                    let sign_bit = (raw_u64 >> (self.bit_length - 1)) & 1;
                    if sign_bit == 1 {
                        let mask = !0u64 << self.bit_length;
                        Ok((raw_u64 | mask) as i64)
                    } else {
                        Ok(raw_u64 as i64)
                    }
                } else {
                    Ok(raw_u64 as i64)
                }
            }
        }
    }

    /// Decode physical engineering value: V_phys = V_raw * scale + offset
    pub fn decode_physical(&self, payload: &[u8]) -> Result<DecodedSignal, String> {
        let raw = self.extract_raw(payload)?;
        let physical = (raw as f64) * self.scale + self.offset;
        let is_out_of_bounds = physical < self.min || physical > self.max;

        Ok(DecodedSignal {
            name: self.name.clone(),
            raw_value: raw,
            physical_value: physical,
            unit: self.unit.clone(),
            min: self.min,
            max: self.max,
            is_out_of_bounds,
        })
    }
}

/// Decoded physical signal container
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedSignal {
    pub name: String,
    pub raw_value: i64,
    pub physical_value: f64,
    pub unit: String,
    pub min: f64,
    pub max: f64,
    pub is_out_of_bounds: bool,
}

/// Message specification in DBC
#[derive(Debug, Clone, PartialEq)]
pub struct MessageDef {
    pub id: u32,
    pub name: String,
    pub dlc: usize,
    pub transmitter: String,
    pub signals: Vec<SignalDef>,
}

impl MessageDef {
    pub fn decode_frame(&self, payload: &[u8]) -> Result<Vec<DecodedSignal>, String> {
        let mut decoded = Vec::new();
        for sig in &self.signals {
            decoded.push(sig.decode_physical(payload)?);
        }
        Ok(decoded)
    }
}

/// Vector DBC Database Container
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DbcDatabase {
    pub messages: HashMap<u32, MessageDef>,
}

impl DbcDatabase {
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
        }
    }

    /// Parse standard Vector DBC format
    pub fn parse(content: &str) -> Result<Self, String> {
        let mut db = DbcDatabase::new();
        let mut current_msg: Option<MessageDef> = None;

        for (line_num, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            if let Some(stripped) = line.strip_prefix("BO_ ") {
                if let Some(msg) = current_msg.take() {
                    db.messages.insert(msg.id, msg);
                }

                // BO_ <can_id> <name>: <dlc> <transmitter>
                let parts: Vec<&str> = stripped.split_whitespace().collect();
                if parts.len() < 4 {
                    return Err(format!(
                        "Line {}: Malformed BO_ definition: '{}'",
                        line_num + 1,
                        line
                    ));
                }

                let id = parts[0].parse::<u32>().map_err(|e| {
                    format!(
                        "Line {}: Invalid message ID '{}': {}",
                        line_num + 1,
                        parts[0],
                        e
                    )
                })?;

                let name = parts[1].trim_end_matches(':').to_string();
                let dlc = parts[2].parse::<usize>().map_err(|e| {
                    format!("Line {}: Invalid DLC '{}': {}", line_num + 1, parts[2], e)
                })?;
                let transmitter = parts[3].to_string();

                current_msg = Some(MessageDef {
                    id,
                    name,
                    dlc,
                    transmitter,
                    signals: Vec::new(),
                });
            } else if let Some(stripped) = line.strip_prefix("SG_ ") {
                if let Some(ref mut msg) = current_msg {
                    let sig = parse_sg_line(stripped, line_num + 1)?;
                    msg.signals.push(sig);
                }
            }
        }

        if let Some(msg) = current_msg {
            db.messages.insert(msg.id, msg);
        }

        Ok(db)
    }

    pub fn get_message(&self, id: u32) -> Option<&MessageDef> {
        self.messages.get(&id)
    }
}

fn parse_sg_line(content: &str, line_num: usize) -> Result<SignalDef, String> {
    // SG_ <name> : <start_bit>|<bit_len>@<endian><sign> (<scale>,<offset>) [<min>|<max>] "<unit>" <receivers>
    // e.g.: SG_ EngineRPM : 0|16@1+ (0.25,0) [0|8000] "rpm" Gateway,Dashboard
    let colon_parts: Vec<&str> = content.split(':').collect();
    if colon_parts.len() != 2 {
        return Err(format!(
            "Line {}: Expected single ':' in SG_ line: '{}'",
            line_num, content
        ));
    }

    let name = colon_parts[0].trim().to_string();
    let body = colon_parts[1].trim();

    // Body tokens: start|len@order (scale,offset) [min|max] "unit" receivers
    let tokens: Vec<&str> = body.split_whitespace().collect();
    if tokens.len() < 4 {
        return Err(format!("Line {}: Malformed SG_ body: '{}'", line_num, body));
    }

    // Token 0: <start_bit>|<bit_len>@<order><sign>
    let bit_spec = tokens[0];
    let pipe_parts: Vec<&str> = bit_spec.split('|').collect();
    if pipe_parts.len() != 2 {
        return Err(format!(
            "Line {}: Malformed bit spec in '{}'",
            line_num, bit_spec
        ));
    }

    let start_bit = pipe_parts[0]
        .parse::<usize>()
        .map_err(|e| format!("Line {}: Invalid start_bit: {}", line_num, e))?;

    let at_parts: Vec<&str> = pipe_parts[1].split('@').collect();
    if at_parts.len() != 2 {
        return Err(format!(
            "Line {}: Expected '@' in bit spec '{}'",
            line_num, pipe_parts[1]
        ));
    }

    let bit_length = at_parts[0]
        .parse::<usize>()
        .map_err(|e| format!("Line {}: Invalid bit_length: {}", line_num, e))?;

    let order_sign = at_parts[1];
    if order_sign.len() < 2 {
        return Err(format!(
            "Line {}: Invalid order/sign '{}'",
            line_num, order_sign
        ));
    }

    let byte_order = match order_sign.chars().next().unwrap() {
        '1' => ByteOrder::IntelLittleEndian,
        '0' => ByteOrder::MotorolaBigEndian,
        c => return Err(format!("Line {}: Invalid byte order '{}'", line_num, c)),
    };

    let value_type = match order_sign.chars().nth(1).unwrap() {
        '+' => ValueType::Unsigned,
        '-' => ValueType::Signed,
        c => return Err(format!("Line {}: Invalid value sign '{}'", line_num, c)),
    };

    // Token 1: (<scale>,<offset>)
    let scale_offset = tokens[1].trim_matches(|c| c == '(' || c == ')');
    let so_parts: Vec<&str> = scale_offset.split(',').collect();
    if so_parts.len() != 2 {
        return Err(format!(
            "Line {}: Malformed scale/offset '{}'",
            line_num, tokens[1]
        ));
    }
    let scale = so_parts[0].parse::<f64>().map_err(|e| e.to_string())?;
    let offset = so_parts[1].parse::<f64>().map_err(|e| e.to_string())?;

    // Token 2: [<min>|<max>]
    let min_max = tokens[2].trim_matches(|c| c == '[' || c == ']');
    let mm_parts: Vec<&str> = min_max.split('|').collect();
    if mm_parts.len() != 2 {
        return Err(format!(
            "Line {}: Malformed min/max '{}'",
            line_num, tokens[2]
        ));
    }
    let min = mm_parts[0].parse::<f64>().map_err(|e| e.to_string())?;
    let max = mm_parts[1].parse::<f64>().map_err(|e| e.to_string())?;

    // Token 3: "<unit>"
    let unit = tokens[3].trim_matches('"').to_string();

    let receivers = if tokens.len() > 4 {
        tokens[4].split(',').map(|s| s.trim().to_string()).collect()
    } else {
        Vec::new()
    };

    Ok(SignalDef {
        name,
        start_bit,
        bit_length,
        byte_order,
        value_type,
        scale,
        offset,
        min,
        max,
        unit,
        receivers,
    })
}
