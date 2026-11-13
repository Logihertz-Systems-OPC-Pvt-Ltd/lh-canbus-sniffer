// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        tests/integration_tests.rs
// Role:          Comprehensive Unit, Integration & Subprocess CLI Test Suite
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

use std::fs;
use std::process::Command;

use lh_canbus::anomaly_detector::{
    calculate_wire_bits, uds_service_name, AnomalyDetector, AnomalyType,
    UDS_DIAGNOSTIC_SESSION_CONTROL, UDS_SECURITY_ACCESS,
};
use lh_canbus::auditor::CanBusAuditor;
use lh_canbus::dbc_decoder::{
    bytes_to_hex, compute_can_crc15, hex_to_bytes, CanFrame, DbcDatabase,
};
use lh_canbus::exporters::Exporters;
use lh_canbus::json::JsonValue;

// ==============================================================================
// 1. SocketCAN Frame Parsing & Hex Helpers
// ==============================================================================

#[test]
fn test_hex_conversion_helpers() {
    let bytes = hex_to_bytes("DEADBEEF01020304").expect("valid hex");
    assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(bytes_to_hex(&bytes), "DEADBEEF01020304");

    // Invalid odd hex length
    assert!(hex_to_bytes("ABC").is_err());
    // Invalid characters
    assert!(hex_to_bytes("ZZ").is_err());
    // Empty hex
    assert_eq!(hex_to_bytes("").unwrap(), Vec::<u8>::new());
}

#[test]
fn test_candump_line_parsing() {
    // Format 1: full with timestamp and interface
    let f1 = CanFrame::parse_candump_line("(1700000000.012345) can0 123#DEADBEEF").unwrap();
    assert_eq!(f1.id, 0x123);
    assert!(!f1.is_extended);
    assert_eq!(f1.interface, "can0");
    assert_eq!(f1.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(f1.dlc, 4);
    assert!((f1.timestamp - 1700000000.012345).abs() < 1e-6);

    // Format 2: interface and frame
    let f2 = CanFrame::parse_candump_line("vcan0 18DAF110#021001").unwrap();
    assert_eq!(f2.id, 0x18DAF110);
    assert!(f2.is_extended);
    assert_eq!(f2.interface, "vcan0");
    assert_eq!(f2.data, vec![0x02, 0x10, 0x01]);

    // Format 3: bare frame
    let f3 = CanFrame::parse_candump_line("456#AABB").unwrap();
    assert_eq!(f3.id, 0x456);
    assert!(!f3.is_extended);
    assert_eq!(f3.data, vec![0xAA, 0xBB]);

    // Invalid format
    assert!(CanFrame::parse_candump_line("invalid_line").is_err());
    assert!(CanFrame::parse_candump_line("").is_err());
}

// ==============================================================================
// 2. DBC Parser & Signal Extraction (Intel & Motorola)
// ==============================================================================

#[test]
fn test_dbc_parsing_from_fixture() {
    let content = fs::read_to_string("fixtures/sample_powertrain.dbc").expect("fixture must exist");
    let db = DbcDatabase::parse(&content).expect("DBC parsing must succeed");

    assert_eq!(db.messages.len(), 2);

    let msg1 = db.get_message(256).expect("Msg 256 (0x100) must exist");
    assert_eq!(msg1.name, "EngineData");
    assert_eq!(msg1.dlc, 8);
    assert_eq!(msg1.transmitter, "EngineECU");
    assert_eq!(msg1.signals.len(), 3);

    let msg2 = db.get_message(512).expect("Msg 512 (0x200) must exist");
    assert_eq!(msg2.name, "ChassisDynamics");
    assert_eq!(msg2.dlc, 8);
    assert_eq!(msg2.signals.len(), 3);
}

#[test]
fn test_intel_little_endian_signal_extraction() {
    let content = fs::read_to_string("fixtures/sample_powertrain.dbc").unwrap();
    let db = DbcDatabase::parse(&content).unwrap();
    let msg = db.get_message(256).unwrap();

    // Payload:
    // Bytes 0-1: EngineRPM (0|16@1+, scale 0.25)
    // 0x2710 = 10000. In Little Endian: Byte 0 = 0x10, Byte 1 = 0x27
    // Physical = 10000 * 0.25 = 2500 rpm.
    // Byte 2: EngineCoolantTemp (16|8@1-, scale 1, offset -40)
    // 0x50 = 80. Physical = 80 * 1 - 40 = 40 degC.
    // Byte 3: ThrottlePosition (24|8@1+, scale 0.392, offset 0)
    // 0x80 = 128. Physical = 128 * 0.392 = 50.176 %
    let payload = vec![0x10, 0x27, 0x50, 0x80, 0x00, 0x00, 0x00, 0x00];
    let decoded = msg.decode_frame(&payload).expect("decoding must succeed");

    assert_eq!(decoded.len(), 3);

    // Signal 1: EngineRPM
    assert_eq!(decoded[0].name, "EngineRPM");
    assert_eq!(decoded[0].raw_value, 10000);
    assert_eq!(decoded[0].physical_value, 2500.0);
    assert!(!decoded[0].is_out_of_bounds);

    // Signal 2: EngineCoolantTemp
    assert_eq!(decoded[1].name, "EngineCoolantTemp");
    assert_eq!(decoded[1].raw_value, 80);
    assert_eq!(decoded[1].physical_value, 40.0);
    assert!(!decoded[1].is_out_of_bounds);

    // Signal 3: ThrottlePosition
    assert_eq!(decoded[2].name, "ThrottlePosition");
    assert_eq!(decoded[2].raw_value, 128);
    assert!((decoded[2].physical_value - 50.176).abs() < 1e-3);
    assert!(!decoded[2].is_out_of_bounds);
}

#[test]
fn test_motorola_big_endian_signal_extraction() {
    let content = fs::read_to_string("fixtures/sample_powertrain.dbc").unwrap();
    let db = DbcDatabase::parse(&content).unwrap();
    let msg = db.get_message(512).unwrap();

    // Signal: SteeringAngle: 39|16@0- (0.1,0) [-500|500] "deg"
    // Byte 4 is MSB, Byte 5 is LSB.
    // Let's test positive angle: 0x01F4 = 500. Physical = 500 * 0.1 = 50.0 deg.
    // Payload: bytes 0..3 dummy, byte 4 = 0x01, byte 5 = 0xF4
    let payload_pos = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0xF4, 0x00, 0x00];
    let decoded_pos = msg.decode_frame(&payload_pos).unwrap();

    let steer_pos = decoded_pos
        .iter()
        .find(|s| s.name == "SteeringAngle")
        .unwrap();
    assert_eq!(steer_pos.raw_value, 500);
    assert_eq!(steer_pos.physical_value, 50.0);
    assert!(!steer_pos.is_out_of_bounds);

    // Let's test negative angle: -500 in 16-bit two's complement is 0xFE0C
    // Byte 4 = 0xFE, Byte 5 = 0x0C. Physical = -500 * 0.1 = -50.0 deg.
    let payload_neg = vec![0x00, 0x00, 0x00, 0x00, 0xFE, 0x0C, 0x00, 0x00];
    let decoded_neg = msg.decode_frame(&payload_neg).unwrap();

    let steer_neg = decoded_neg
        .iter()
        .find(|s| s.name == "SteeringAngle")
        .unwrap();
    assert_eq!(steer_neg.raw_value, -500);
    assert_eq!(steer_neg.physical_value, -50.0);
    assert!(!steer_neg.is_out_of_bounds);
}

#[test]
fn test_signal_out_of_bounds_detection() {
    let content = fs::read_to_string("fixtures/sample_powertrain.dbc").unwrap();
    let db = DbcDatabase::parse(&content).unwrap();
    let msg = db.get_message(256).unwrap();

    // EngineRPM max is 8000. Raw value 40000 * 0.25 = 10000 rpm (> 8000!)
    // 40000 = 0x9C40. Little endian: Byte 0 = 0x40, Byte 1 = 0x9C
    let payload_over = vec![0x40, 0x9C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let decoded = msg.decode_frame(&payload_over).unwrap();

    assert_eq!(decoded[0].physical_value, 10000.0);
    assert!(decoded[0].is_out_of_bounds);
}

#[test]
fn test_bosch_can_crc15_calculation() {
    let empty = compute_can_crc15(&[]);
    assert_eq!(empty, 0);

    let data1 = vec![0x01];
    let crc1 = compute_can_crc15(&data1);
    assert_ne!(crc1, 0);

    let data2 = vec![0x01, 0x02, 0x03, 0x04];
    let crc2 = compute_can_crc15(&data2);
    assert_ne!(crc2, 0);

    // Bit flip detection: changing one bit changes CRC
    let data2_corrupt = vec![0x01, 0x02, 0x03, 0x05];
    let crc2_corrupt = compute_can_crc15(&data2_corrupt);
    assert_ne!(crc2, crc2_corrupt);
}

// ==============================================================================
// 3. Anomaly Detector & Intrusion Detection Tests
// ==============================================================================

#[test]
fn test_wire_bits_and_bus_utilization() {
    // 8 bytes DLC: (47 + 64) * 1.20 = 111 * 1.20 = 133.2 -> 133 bits
    assert_eq!(calculate_wire_bits(8), 133);
    assert_eq!(calculate_wire_bits(0), 56);

    let mut detector = AnomalyDetector::new(500_000);
    let frames = vec![
        CanFrame::new(0x100, false, vec![0; 8], 0.0, "can0".to_string()),
        CanFrame::new(0x100, false, vec![0; 8], 0.02, "can0".to_string()),
    ];
    let report = detector.analyze_trace(&frames, None);
    assert_eq!(report.total_frames, 2);
    assert!(report.bus_utilization_percent < 80.0);
}

#[test]
fn test_inter_arrival_masquerade_injection() {
    let mut detector = AnomalyDetector::new(500_000);
    detector.set_nominal_interval(0x100, 0.020); // 20ms expected

    let frames = vec![
        CanFrame::new(0x100, false, vec![0; 8], 0.000, "can0".to_string()),
        CanFrame::new(0x100, false, vec![0; 8], 0.020, "can0".to_string()),
        // Attacker injects spoofed frame only 3ms later (0.003s < 0.35 * 0.020s = 0.007s)
        CanFrame::new(0x100, false, vec![0xFF; 8], 0.023, "can0".to_string()),
    ];

    let report = detector.analyze_trace(&frames, None);
    assert!(!report.anomalies.is_empty());
    assert!(matches!(
        report.anomalies[0].anomaly_type,
        AnomalyType::FrameInjection(0x100, _, _)
    ));
}

#[test]
fn test_uds_diagnostic_intrusion_detection() {
    let mut detector = AnomalyDetector::new(500_000);

    // Frame on 0x7DF with UDS 0x10 (DiagnosticSessionControl)
    let frames = vec![
        CanFrame::new(
            0x7DF,
            false,
            vec![0x02, 0x10, 0x01, 0, 0, 0, 0, 0],
            1.0,
            "can0".to_string(),
        ),
        CanFrame::new(
            0x7E0,
            false,
            vec![0x02, 0x27, 0x01, 0, 0, 0, 0, 0],
            1.05,
            "can0".to_string(),
        ),
    ];

    let report = detector.analyze_trace(&frames, None);
    assert_eq!(report.anomalies.len(), 2);
    assert_eq!(
        uds_service_name(UDS_DIAGNOSTIC_SESSION_CONTROL),
        "DiagnosticSessionControl (0x10)"
    );
    assert_eq!(
        uds_service_name(UDS_SECURITY_ACCESS),
        "SecurityAccess (0x27)"
    );
}

#[test]
fn test_analyze_candump_fixture_file() {
    let content = fs::read_to_string("fixtures/sample_candump.log").unwrap();
    let mut frames = Vec::new();
    for line in content.lines() {
        if let Ok(f) = CanFrame::parse_candump_line(line) {
            frames.push(f);
        }
    }
    assert_eq!(frames.len(), 12);

    let dbc_content = fs::read_to_string("fixtures/sample_powertrain.dbc").unwrap();
    let dbc = DbcDatabase::parse(&dbc_content).unwrap();

    let mut detector = AnomalyDetector::new(500_000);
    let report = detector.analyze_trace(&frames, Some(&dbc));

    // Must flag the injected spoof frame and the 2 UDS frames
    assert!(report.anomalies.len() >= 3);
}

// ==============================================================================
// 4. JSON Lexer & Parser Tests
// ==============================================================================

#[test]
fn test_json_parser_primitives_and_nested() {
    let json_text = r#"{
        "name": "CAN-Policy",
        "bitrate": 500000,
        "load_limit": 75.5,
        "enabled": true,
        "disabled": false,
        "extra": null,
        "ids": [256, 512, 1024],
        "nested": {
            "key": "value"
        }
    }"#;

    let val = JsonValue::parse(json_text).expect("JSON parsing must succeed");
    assert_eq!(val.get("name").and_then(|v| v.as_str()), Some("CAN-Policy"));
    assert_eq!(val.get("bitrate").and_then(|v| v.as_u64()), Some(500000));
    assert_eq!(val.get("load_limit").and_then(|v| v.as_f64()), Some(75.5));
    assert_eq!(val.get("enabled").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(val.get("disabled").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(val.get("extra"), Some(&JsonValue::Null));

    let ids = val.get("ids").and_then(|v| v.as_array()).unwrap();
    assert_eq!(ids.len(), 3);
    assert_eq!(ids[0].as_u64(), Some(256));

    let nested = val.get("nested").unwrap();
    assert_eq!(nested.get("key").and_then(|v| v.as_str()), Some("value"));

    // Trailing chars error
    assert!(JsonValue::parse("true trailing").is_err());
}

// ==============================================================================
// 5. 10-Rule Auditor & Posture Scoring Tests
// ==============================================================================

#[test]
fn test_hardened_canbus_policy_passes_all_rules() {
    let content = fs::read_to_string("fixtures/hardened_canbus_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();

    let report = CanBusAuditor::audit_policy(&json, "fixtures/hardened_canbus_policy.json");
    assert_eq!(report.score, 100);
    assert_eq!(report.status, "PASSED");
    assert_eq!(report.passed_rules, 10);
    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.critical_count, 0);
    assert_eq!(report.high_count, 0);
    assert_eq!(report.medium_count, 0);
    assert_eq!(report.low_count, 0);
}

#[test]
fn test_vulnerable_canbus_policy_triggers_all_rules() {
    let content = fs::read_to_string("fixtures/vulnerable_canbus_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();

    let report = CanBusAuditor::audit_policy(&json, "fixtures/vulnerable_canbus_policy.json");
    assert_eq!(report.score, 0);
    assert_eq!(report.status, "FAILED");
    assert_eq!(report.passed_rules, 0);
    assert_eq!(report.findings.len(), 10);
    assert_eq!(report.critical_count, 3);
    assert_eq!(report.high_count, 4);
    assert_eq!(report.medium_count, 2);
    assert_eq!(report.low_count, 1);
}

#[test]
fn test_isolated_single_rule_violations() {
    let content = fs::read_to_string("fixtures/hardened_canbus_policy.json").unwrap();
    let base_json = JsonValue::parse(&content).unwrap();

    // 1. LH-CAN-001 (CRITICAL, 25 deduction -> 75)
    let mut p1 = base_json.clone();
    if let JsonValue::Object(ref mut entries) = p1 {
        for (k, v) in entries {
            if k == "secoc_authentication_enabled" {
                *v = JsonValue::Bool(false);
            }
        }
    }
    let rep1 = CanBusAuditor::audit_policy(&p1, "p1.json");
    assert_eq!(rep1.score, 75);
    assert_eq!(rep1.findings[0].rule_id, "LH-CAN-001");

    // 2. LH-CAN-004 (HIGH, 10 deduction -> 90)
    let mut p4 = base_json.clone();
    if let JsonValue::Object(ref mut entries) = p4 {
        for (k, v) in entries {
            if k == "can_raw_filter_allowlist_enabled" {
                *v = JsonValue::Bool(false);
            }
        }
    }
    let rep4 = CanBusAuditor::audit_policy(&p4, "p4.json");
    assert_eq!(rep4.score, 90);
    assert_eq!(rep4.findings[0].rule_id, "LH-CAN-004");

    // 3. LH-CAN-008 (MEDIUM, 4 deduction -> 96)
    let mut p8 = base_json.clone();
    if let JsonValue::Object(ref mut entries) = p8 {
        for (k, v) in entries {
            if k == "gateway_domain_isolation" {
                *v = JsonValue::Bool(false);
            }
        }
    }
    let rep8 = CanBusAuditor::audit_policy(&p8, "p8.json");
    assert_eq!(rep8.score, 96);
    assert_eq!(rep8.findings[0].rule_id, "LH-CAN-008");

    // 4. LH-CAN-010 (LOW, 1 deduction -> 99)
    let mut p10 = base_json.clone();
    if let JsonValue::Object(ref mut entries) = p10 {
        for (k, v) in entries {
            if k == "strict_dlc_validation" {
                *v = JsonValue::Bool(false);
            }
        }
    }
    let rep10 = CanBusAuditor::audit_policy(&p10, "p10.json");
    assert_eq!(rep10.score, 99);
    assert_eq!(rep10.findings[0].rule_id, "LH-CAN-010");

    // Combined: Rule 1 + Rule 4 = 25 + 10 = 35 deduction -> 65
    let mut p_comb = base_json;
    if let JsonValue::Object(ref mut entries) = p_comb {
        for (k, v) in entries {
            if k == "secoc_authentication_enabled" {
                *v = JsonValue::Bool(false);
            }
            if k == "can_raw_filter_allowlist_enabled" {
                *v = JsonValue::Bool(false);
            }
        }
    }
    let rep_comb = CanBusAuditor::audit_policy(&p_comb, "p_comb.json");
    assert_eq!(rep_comb.score, 65);
    assert_eq!(rep_comb.findings.len(), 2);
}

// ==============================================================================
// 6. Exporters Tests
// ==============================================================================

#[test]
fn test_exporters_table_json_sarif() {
    let content = fs::read_to_string("fixtures/vulnerable_canbus_policy.json").unwrap();
    let json = JsonValue::parse(&content).unwrap();
    let report = CanBusAuditor::audit_policy(&json, "fixtures/vulnerable_canbus_policy.json");

    // Table
    let table = Exporters::format_table(&report);
    assert!(table.contains("Logihertz SocketCAN Security Posture Auditor"));
    assert!(table.contains("LH-CAN-001"));
    assert!(table.contains("FAILED"));

    // JSON
    let json_str = Exporters::format_json(&report);
    let parsed_j = JsonValue::parse(&json_str).expect("Exported JSON must parse");
    assert_eq!(parsed_j.get("score").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        parsed_j
            .get("findings")
            .and_then(|v| v.as_array())
            .unwrap()
            .len(),
        10
    );

    // SARIF v2.1.0
    let sarif_str = Exporters::format_sarif(&report);
    let parsed_s = JsonValue::parse(&sarif_str).expect("Exported SARIF must parse");
    assert_eq!(
        parsed_s.get("version").and_then(|v| v.as_str()),
        Some("2.1.0")
    );
    assert!(parsed_s.get("$schema").is_some());
    let runs = parsed_s.get("runs").and_then(|v| v.as_array()).unwrap();
    assert_eq!(runs.len(), 1);
    let results = runs[0].get("results").and_then(|v| v.as_array()).unwrap();
    assert_eq!(results.len(), 10);
}

// ==============================================================================
// 7. CLI Subprocess Invocation & Smoke Tests
// ==============================================================================

#[test]
fn test_cli_subcommands_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_lh-canbus");

    // 1. --version (exit 0)
    let s_ver = Command::new(bin).arg("--version").output().unwrap();
    assert_eq!(s_ver.status.code(), Some(0));
    let ver_out = String::from_utf8_lossy(&s_ver.stdout);
    assert!(ver_out.contains("lh-canbus 0.1.0"));

    // 2. --help (exit 0)
    let s_help = Command::new(bin).arg("--help").output().unwrap();
    assert_eq!(s_help.status.code(), Some(0));

    // 3. scan hardened (exit 0)
    let s_scan_pass = Command::new(bin)
        .args(["scan", "fixtures/hardened_canbus_policy.json"])
        .output()
        .unwrap();
    assert_eq!(s_scan_pass.status.code(), Some(0));

    // 4. scan vulnerable (exit 1)
    let s_scan_fail = Command::new(bin)
        .args(["scan", "fixtures/vulnerable_canbus_policy.json"])
        .output()
        .unwrap();
    assert_eq!(s_scan_fail.status.code(), Some(1));

    // 5. scan missing file (exit 2)
    let s_scan_err = Command::new(bin)
        .args(["scan", "nonexistent_file.json"])
        .output()
        .unwrap();
    assert_eq!(s_scan_err.status.code(), Some(2));

    // 6. decode DBC frame (exit 0)
    let s_decode = Command::new(bin)
        .args([
            "decode",
            "--dbc",
            "fixtures/sample_powertrain.dbc",
            "--frame",
            "100#1027140000000000",
        ])
        .output()
        .unwrap();
    assert_eq!(s_decode.status.code(), Some(0));
    let dec_out = String::from_utf8_lossy(&s_decode.stdout);
    assert!(dec_out.contains("EngineRPM"));
    assert!(dec_out.contains("2500.00"));

    // 7. analyze-trace (exit 1 due to intrusions in sample_candump.log)
    let s_trace = Command::new(bin)
        .args([
            "analyze-trace",
            "fixtures/sample_candump.log",
            "--dbc",
            "fixtures/sample_powertrain.dbc",
        ])
        .output()
        .unwrap();
    assert_eq!(s_trace.status.code(), Some(1));
    let trace_out = String::from_utf8_lossy(&s_trace.stdout);
    assert!(trace_out.contains("INTRUSIONS / ANOMALIES DETECTED"));

    // 8. verify-crc (exit 0)
    let s_crc = Command::new(bin)
        .args(["verify-crc", "1027140000000000"])
        .output()
        .unwrap();
    assert_eq!(s_crc.status.code(), Some(0));
    let crc_out = String::from_utf8_lossy(&s_crc.stdout);
    assert!(crc_out.contains("Computed CRC-15"));

    // 9. Unknown command (exit 2)
    let s_bad = Command::new(bin).arg("unknown_command").output().unwrap();
    assert_eq!(s_bad.status.code(), Some(2));
}
