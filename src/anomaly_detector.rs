// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        src/anomaly_detector.rs
// Role:          Bus-Load Utilization, Inter-Arrival Spoofing IDS & UDS Diagnostic Guard
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

//! Real-time anomaly detection, bus utilization modeling, and UDS intrusion guards.

use std::collections::HashMap;

use crate::dbc_decoder::{CanFrame, DbcDatabase};

/// Known ISO 14229 Unified Diagnostic Services (UDS) Service IDs
pub const UDS_DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;
pub const UDS_ECU_RESET: u8 = 0x11;
pub const UDS_SECURITY_ACCESS: u8 = 0x27;
pub const UDS_COMMUNICATION_CONTROL: u8 = 0x28;
pub const UDS_WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
pub const UDS_ROUTINE_CONTROL: u8 = 0x31;
pub const UDS_REQUEST_DOWNLOAD: u8 = 0x34;

pub fn uds_service_name(sid: u8) -> &'static str {
    match sid {
        UDS_DIAGNOSTIC_SESSION_CONTROL => "DiagnosticSessionControl (0x10)",
        UDS_ECU_RESET => "ECUReset (0x11)",
        UDS_SECURITY_ACCESS => "SecurityAccess (0x27)",
        UDS_COMMUNICATION_CONTROL => "CommunicationControl (0x28)",
        UDS_WRITE_DATA_BY_IDENTIFIER => "WriteDataByIdentifier (0x2E)",
        UDS_ROUTINE_CONTROL => "RoutineControl (0x31)",
        UDS_REQUEST_DOWNLOAD => "RequestDownload / Firmware Flash (0x34)",
        _ => "Unknown UDS Service",
    }
}

pub fn is_uds_or_obd2_id(id: u32) -> bool {
    id == 0x7DF || (0x7E0..=0x7EF).contains(&id)
}

/// Calculate wire bits for a CAN 2.0A frame of given data length D
/// Standard CAN 2.0A: 47 overhead bits + 8 * D data bits + worst-case 20% bit stuffing
pub fn calculate_wire_bits(dlc: usize) -> u32 {
    let raw = 47 + 8 * dlc;
    ((raw as f64) * 1.20).floor() as u32
}

/// Classification of detected anomalies
#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyType {
    BusSaturation(f64),
    DominantIdFlood(u32, usize),
    FrameInjection(u32, f64, f64),
    UnauthorizedUds(u32, u8, &'static str),
    SignalOutOfBounds(u32, String, f64, f64, f64),
}

/// Individual intrusion finding
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyFinding {
    pub timestamp: f64,
    pub can_id: u32,
    pub severity: &'static str,
    pub anomaly_type: AnomalyType,
    pub description: String,
}

/// Analysis report generated from trace processing
#[derive(Debug, Clone, PartialEq)]
pub struct TraceAnalysisReport {
    pub total_frames: usize,
    pub time_window_seconds: f64,
    pub bus_bitrate: u32,
    pub bus_utilization_percent: f64,
    pub id_counts: HashMap<u32, usize>,
    pub anomalies: Vec<AnomalyFinding>,
}

/// Real-time Intrusion Detection Engine
pub struct AnomalyDetector {
    bitrate: u32,
    nominal_intervals: HashMap<u32, f64>,
    last_seen_timestamps: HashMap<u32, f64>,
    id_counts: HashMap<u32, usize>,
}

impl AnomalyDetector {
    pub fn new(bitrate: u32) -> Self {
        Self {
            bitrate,
            nominal_intervals: HashMap::new(),
            last_seen_timestamps: HashMap::new(),
            id_counts: HashMap::new(),
        }
    }

    pub fn set_nominal_interval(&mut self, can_id: u32, interval_seconds: f64) {
        self.nominal_intervals.insert(can_id, interval_seconds);
    }

    /// Analyze a sequence of CAN frames (e.g. from candump) with optional DBC decoding
    pub fn analyze_trace(
        &mut self,
        frames: &[CanFrame],
        dbc: Option<&DbcDatabase>,
    ) -> TraceAnalysisReport {
        let mut anomalies = Vec::new();
        if frames.is_empty() {
            return TraceAnalysisReport {
                total_frames: 0,
                time_window_seconds: 0.0,
                bus_bitrate: self.bitrate,
                bus_utilization_percent: 0.0,
                id_counts: HashMap::new(),
                anomalies: Vec::new(),
            };
        }

        let first_ts = frames.first().map(|f| f.timestamp).unwrap_or(0.0);
        let last_ts = frames.last().map(|f| f.timestamp).unwrap_or(0.0);
        let time_window = if last_ts > first_ts {
            last_ts - first_ts
        } else {
            1.0 // fallback
        };

        // 1. First pass: compute empirical intervals if not configured
        let mut id_diffs: HashMap<u32, Vec<f64>> = HashMap::new();
        let mut prev_ts: HashMap<u32, f64> = HashMap::new();

        for frame in frames {
            if let Some(&p) = prev_ts.get(&frame.id) {
                let dt = frame.timestamp - p;
                if dt > 0.0001 {
                    id_diffs.entry(frame.id).or_default().push(dt);
                }
            }
            prev_ts.insert(frame.id, frame.timestamp);
        }

        for (id, diffs) in id_diffs {
            if !self.nominal_intervals.contains_key(&id) && diffs.len() >= 3 {
                // Median or mean interval
                let sum: f64 = diffs.iter().sum();
                let mean = sum / (diffs.len() as f64);
                self.nominal_intervals.insert(id, mean);
            }
        }

        // 2. Second pass: intrusion detection and wire utilization
        let mut total_wire_bits: u64 = 0;
        let mut dominant_zero_count = 0;

        for frame in frames {
            *self.id_counts.entry(frame.id).or_insert(0) += 1;
            total_wire_bits += calculate_wire_bits(frame.dlc) as u64;

            if frame.id == 0x000 {
                dominant_zero_count += 1;
            }

            // A. Inter-arrival spoofing check: dt < 0.35 * T_nom
            if let Some(&last_t) = self.last_seen_timestamps.get(&frame.id) {
                let dt = frame.timestamp - last_t;
                if let Some(&t_nom) = self.nominal_intervals.get(&frame.id) {
                    if t_nom > 0.001 && dt < 0.35 * t_nom {
                        anomalies.push(AnomalyFinding {
                            timestamp: frame.timestamp,
                            can_id: frame.id,
                            severity: "HIGH",
                            anomaly_type: AnomalyType::FrameInjection(frame.id, dt, t_nom),
                            description: format!(
                                "Inter-arrival timing anomaly on ID 0x{:03X}: delta_t={:.4}s (< 0.35 * T_nom={:.4}s) indicates injected masquerade frame.",
                                frame.id, dt, t_nom
                            ),
                        });
                    }
                }
            }
            self.last_seen_timestamps.insert(frame.id, frame.timestamp);

            // B. ISO 14229 UDS Diagnostic Guard
            if is_uds_or_obd2_id(frame.id) && !frame.data.is_empty() {
                // Check Byte 0 or Byte 1 for critical UDS SID
                let sid = if frame.data.len() >= 2 && frame.data[0] <= 7 {
                    frame.data[1] // ISO-TP Single Frame format: [Length, SID, ...]
                } else {
                    frame.data[0]
                };

                match sid {
                    UDS_DIAGNOSTIC_SESSION_CONTROL
                    | UDS_ECU_RESET
                    | UDS_SECURITY_ACCESS
                    | UDS_COMMUNICATION_CONTROL
                    | UDS_WRITE_DATA_BY_IDENTIFIER
                    | UDS_ROUTINE_CONTROL
                    | UDS_REQUEST_DOWNLOAD => {
                        let s_name = uds_service_name(sid);
                        anomalies.push(AnomalyFinding {
                            timestamp: frame.timestamp,
                            can_id: frame.id,
                            severity: "CRITICAL",
                            anomaly_type: AnomalyType::UnauthorizedUds(frame.id, sid, s_name),
                            description: format!(
                                "Unauthorized diagnostic intrusion on ID 0x{:03X}: requested critical service '{}'.",
                                frame.id, s_name
                            ),
                        });
                    }
                    _ => {}
                }
            }

            // C. DBC physical bounds check if DBC is provided
            if let Some(dbc_db) = dbc {
                if let Some(msg_def) = dbc_db.get_message(frame.id) {
                    if let Ok(signals) = msg_def.decode_frame(&frame.data) {
                        for sig in signals {
                            if sig.is_out_of_bounds {
                                anomalies.push(AnomalyFinding {
                                    timestamp: frame.timestamp,
                                    can_id: frame.id,
                                    severity: "HIGH",
                                    anomaly_type: AnomalyType::SignalOutOfBounds(
                                        frame.id,
                                        sig.name.clone(),
                                        sig.physical_value,
                                        sig.min,
                                        sig.max,
                                    ),
                                    description: format!(
                                        "Signal '{}' on ID 0x{:03X} out of physical bounds: value={:.2} {} outside [{:.2}, {:.2}].",
                                        sig.name, frame.id, sig.physical_value, sig.unit, sig.min, sig.max
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        // C. Dominant ID 0x000 flood check
        if dominant_zero_count > 5 {
            anomalies.push(AnomalyFinding {
                timestamp: last_ts,
                can_id: 0x000,
                severity: "CRITICAL",
                anomaly_type: AnomalyType::DominantIdFlood(0x000, dominant_zero_count),
                description: format!(
                    "Dominant ID 0x000 flood detected: {} dominant frames observed, threatening bus arbitration starvation.",
                    dominant_zero_count
                ),
            });
        }

        // D. Bus utilization calculation: U_bus = (total_bits / (bitrate * T_window)) * 100
        let max_capacity_bits = (self.bitrate as f64) * time_window;
        let bus_util = if max_capacity_bits > 0.0 {
            ((total_wire_bits as f64) / max_capacity_bits) * 100.0
        } else {
            0.0
        };

        if bus_util > 80.0 {
            anomalies.push(AnomalyFinding {
                timestamp: last_ts,
                can_id: 0,
                severity: "HIGH",
                anomaly_type: AnomalyType::BusSaturation(bus_util),
                description: format!(
                    "CAN bus utilization saturation: {:.2}% exceeds safe threshold (80.0%).",
                    bus_util
                ),
            });
        }

        TraceAnalysisReport {
            total_frames: frames.len(),
            time_window_seconds: time_window,
            bus_bitrate: self.bitrate,
            bus_utilization_percent: bus_util,
            id_counts: self.id_counts.clone(),
            anomalies,
        }
    }
}
