// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        src/main.rs
// Role:          Unified CLI Entrypoint for Scanning, Decoding, Trace Analysis & CRC
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::process;

use lh_canbus::anomaly_detector::AnomalyDetector;
use lh_canbus::auditor::CanBusAuditor;
use lh_canbus::dbc_decoder::{compute_can_crc15, hex_to_bytes, CanFrame, DbcDatabase};
use lh_canbus::exporters::Exporters;
use lh_canbus::json::JsonValue;

fn print_version() {
    println!("lh-canbus 0.1.0");
    println!("Logihertz Automotive & Industrial SocketCAN Sniffer and Security Auditor");
    println!("Organization: Logihertz Systems (OPC) Private Limited (https://logihertz.com/)");
    println!("Developer:    Sameer Tawade <ops@logihertz.com>");
    println!("License:      Apache-2.0");
}

fn print_usage(prog: &str) {
    println!("Usage: {} <command> [options]\n", prog);
    println!("Commands:");
    println!(
        "  scan <policy.json>         Audit CAN bus deployment policy against 10 security rules"
    );
    println!("  decode                     Decode CAN frame signals using Vector DBC database");
    println!(
        "  analyze-trace <trace.log>  Inspect candump trace for DoS saturation and injected frames"
    );
    println!("  verify-crc <hex_payload>   Compute and verify Bosch CAN 2.0 15-bit CRC (0x4599)");
    println!("  --version, -v              Display version and attribution");
    println!("  --help, -h                 Display this comprehensive usage guide\n");
    println!("Scan Options:");
    println!("  --format <table|json|sarif> Output report format (default: table)");
    println!("  --output <file>             Write report findings to target file\n");
    println!("Decode Options:");
    println!("  --dbc <file.dbc>            Path to Vector DBC database");
    println!("  --frame <id#hex_payload>    CAN frame string (e.g. 100#0102030405060708)\n");
    println!("Analyze Trace Options:");
    println!("  --dbc <file.dbc>            Optional DBC database for signal out-of-bounds checks");
    println!("  --bitrate <bps>             Bus nominal bitrate (default: 500000)\n");
    println!("Exit Codes:");
    println!("  0                          Success / Audit Passed / Clean Trace (0 Anomalies)");
    println!("  1                          Security Findings Detected / Trace Anomalies Detected");
    println!("  2                          Invalid CLI arguments, parse error, or missing file");
}

fn cmd_scan(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("Error: 'scan' requires a policy configuration JSON path.");
        return 2;
    }

    let policy_path = &args[0];
    let mut format = "table".to_string();
    let mut output_path = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                if i + 1 < args.len() {
                    format = args[i + 1].to_lowercase();
                    i += 2;
                } else {
                    eprintln!("Error: --format requires an argument.");
                    return 2;
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    output_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --output requires an argument.");
                    return 2;
                }
            }
            unknown => {
                eprintln!("Error: Unknown option '{}' for scan.", unknown);
                return 2;
            }
        }
    }

    let content = match fs::read_to_string(policy_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Cannot open policy file '{}': {}", policy_path, e);
            return 2;
        }
    };

    let policy_json = match JsonValue::parse(&content) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error: JSON parse failed for '{}': {}", policy_path, e);
            return 2;
        }
    };

    let report = CanBusAuditor::audit_policy(&policy_json, policy_path);

    let output_str = match format.as_str() {
        "table" => Exporters::format_table(&report),
        "json" => Exporters::format_json(&report),
        "sarif" => Exporters::format_sarif(&report),
        _ => {
            eprintln!(
                "Error: Invalid format '{}'. Choose table, json, or sarif.",
                format
            );
            return 2;
        }
    };

    if !output_path.is_empty() {
        if let Err(e) = fs::write(&output_path, output_str) {
            eprintln!(
                "Error: Failed to write to output file '{}': {}",
                output_path, e
            );
            return 2;
        }
        println!("Audit findings saved to {}", output_path);
    } else {
        println!("{}", output_str);
    }

    if report.score == 100 {
        0
    } else {
        1
    }
}

fn cmd_decode(args: &[String]) -> i32 {
    let mut dbc_path = String::new();
    let mut frame_str = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dbc" => {
                if i + 1 < args.len() {
                    dbc_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --dbc requires a path argument.");
                    return 2;
                }
            }
            "--frame" => {
                if i + 1 < args.len() {
                    frame_str = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --frame requires a CAN frame argument (e.g. 100#112233).");
                    return 2;
                }
            }
            unknown => {
                eprintln!("Error: Unknown option '{}' for decode.", unknown);
                return 2;
            }
        }
    }

    if dbc_path.is_empty() || frame_str.is_empty() {
        eprintln!("Error: 'decode' requires both --dbc <file.dbc> and --frame <id#hex>.");
        return 2;
    }

    let dbc_content = match fs::read_to_string(&dbc_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to read DBC file '{}': {}", dbc_path, e);
            return 2;
        }
    };

    let dbc = match DbcDatabase::parse(&dbc_content) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error parsing DBC file '{}': {}", dbc_path, e);
            return 2;
        }
    };

    let frame = match CanFrame::parse_candump_line(&frame_str) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error parsing CAN frame '{}': {}", frame_str, e);
            return 2;
        }
    };

    let msg_def = match dbc.get_message(frame.id) {
        Some(m) => m,
        None => {
            eprintln!(
                "Error: Message ID 0x{:03X} not found in DBC '{}'.",
                frame.id, dbc_path
            );
            return 2;
        }
    };

    let decoded = match msg_def.decode_frame(&frame.data) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error decoding frame signals: {}", e);
            return 2;
        }
    };

    println!("\n======================================================================");
    println!("       LOGIHERTZ SOCKETCAN DBC SIGNAL DECODER REPORT");
    println!("======================================================================");
    println!(" Message ID:       0x{:03X} ({})", frame.id, frame.id);
    println!(" Message Name:     {}", msg_def.name);
    println!(" Transmitter:      {}", msg_def.transmitter);
    println!(" Payload Length:   {} bytes", frame.dlc);
    println!(
        " Payload Hex:      {}",
        lh_canbus::dbc_decoder::bytes_to_hex(&frame.data)
    );
    println!(" Signals Decoded:  {}", decoded.len());
    println!("----------------------------------------------------------------------");
    println!(
        "{:<24} | {:<12} | {:<16} | {:<8} | Range Bounds",
        "Signal Name", "Raw Value", "Physical Value", "Unit"
    );
    println!("----------------------------------------------------------------------");

    let mut any_out_of_bounds = false;
    for sig in &decoded {
        let bounds_str = if sig.is_out_of_bounds {
            any_out_of_bounds = true;
            format!("OUT OF RANGE! [{:.1}, {:.1}]", sig.min, sig.max)
        } else {
            format!("OK [{:.1}, {:.1}]", sig.min, sig.max)
        };

        println!(
            "{:<24} | {:<12} | {:<16.2} | {:<8} | {}",
            sig.name, sig.raw_value, sig.physical_value, sig.unit, bounds_str
        );
    }
    println!("======================================================================\n");

    if any_out_of_bounds {
        1
    } else {
        0
    }
}

fn cmd_analyze_trace(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("Error: 'analyze-trace' requires a candump log file path.");
        return 2;
    }

    let trace_path = &args[0];
    let mut dbc_path = String::new();
    let mut bitrate = 500_000u32;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dbc" => {
                if i + 1 < args.len() {
                    dbc_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --dbc requires a path argument.");
                    return 2;
                }
            }
            "--bitrate" => {
                if i + 1 < args.len() {
                    bitrate = match args[i + 1].parse() {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("Error: Invalid bitrate '{}': {}", args[i + 1], e);
                            return 2;
                        }
                    };
                    i += 2;
                } else {
                    eprintln!("Error: --bitrate requires an integer argument.");
                    return 2;
                }
            }
            unknown => {
                eprintln!("Error: Unknown option '{}' for analyze-trace.", unknown);
                return 2;
            }
        }
    }

    let trace_content = match fs::read_to_string(trace_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Cannot open trace file '{}': {}", trace_path, e);
            return 2;
        }
    };

    let mut frames = Vec::new();
    for line in trace_content.lines() {
        if let Ok(f) = CanFrame::parse_candump_line(line) {
            frames.push(f);
        }
    }

    if frames.is_empty() {
        eprintln!(
            "Error: No valid CAN frames parsed from trace '{}'.",
            trace_path
        );
        return 2;
    }

    let dbc = if !dbc_path.is_empty() {
        match fs::read_to_string(&dbc_path) {
            Ok(c) => match DbcDatabase::parse(&c) {
                Ok(db) => Some(db),
                Err(e) => {
                    eprintln!("Warning: Failed to parse DBC '{}': {}", dbc_path, e);
                    None
                }
            },
            Err(e) => {
                eprintln!("Warning: Failed to read DBC '{}': {}", dbc_path, e);
                None
            }
        }
    } else {
        None
    };

    let mut detector = AnomalyDetector::new(bitrate);
    let report = detector.analyze_trace(&frames, dbc.as_ref());

    println!("\n======================================================================");
    println!("       LOGIHERTZ SOCKETCAN TRACE INTRUSION DETECTION REPORT");
    println!("======================================================================");
    println!(" Trace File:          {}", trace_path);
    println!(" Total Frames Parsed: {}", report.total_frames);
    println!(
        " Trace Duration:      {:.3} seconds",
        report.time_window_seconds
    );
    println!(" Bus Nominal Bitrate: {} bps", report.bus_bitrate);
    println!(
        " Wire Utilization:    {:.2} %",
        report.bus_utilization_percent
    );
    println!(" Unique CAN IDs:      {}", report.id_counts.len());
    println!(" Total Anomalies:     {}", report.anomalies.len());
    println!("======================================================================");

    if report.anomalies.is_empty() {
        println!(" [OK] No timing masquerades, UDS intrusions, or bus saturation detected.");
        println!("      Trace verified clean and compliant with safe operational norms.\n");
        0
    } else {
        println!("\nDetected Anomaly Findings:");
        for (idx, a) in report.anomalies.iter().enumerate() {
            println!(
                " [{}] [{}] Timestamp: {:.4}s | ID: 0x{:03X} | {}",
                idx + 1,
                a.severity,
                a.timestamp,
                a.can_id,
                a.description
            );
        }
        println!("\nStatus: INTRUSIONS / ANOMALIES DETECTED IN TRACE\n");
        1
    }
}

fn cmd_verify_crc(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("Error: 'verify-crc' requires a hex payload argument.");
        return 2;
    }

    let hex_str = &args[0];
    let bytes = match hex_to_bytes(hex_str) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error parsing hex payload: {}", e);
            return 2;
        }
    };

    let crc15 = compute_can_crc15(&bytes);

    println!("\n======================================================================");
    println!("       LOGIHERTZ BOSCH CAN 2.0 CRC-15 VERIFICATION REPORT");
    println!("======================================================================");
    println!(" Payload Length:      {} bytes", bytes.len());
    println!(" Payload Hex:         {}", hex_str);
    println!(" Generator Poly:      x^15 + x^14 + x^10 + x^8 + x^7 + x^4 + x^3 + 1 (0x4599)");
    println!(" Computed CRC-15:     0x{:04X} ({})", crc15, crc15);
    println!(" Binary CRC (15-bit): {:015b}", crc15);
    println!(" Status:              CRC COMPUTED SUCCESSFULLY");
    println!("======================================================================\n");

    0
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage("lh-canbus");
        process::exit(2);
    }

    let cmd = &args[1];
    let exit_code = match cmd.as_str() {
        "--version" | "-v" => {
            print_version();
            0
        }
        "--help" | "-h" => {
            print_usage("lh-canbus");
            0
        }
        "scan" => cmd_scan(&args[2..]),
        "decode" => cmd_decode(&args[2..]),
        "analyze-trace" => cmd_analyze_trace(&args[2..]),
        "verify-crc" => cmd_verify_crc(&args[2..]),
        unknown => {
            eprintln!("Error: Unknown command '{}'.", unknown);
            print_usage("lh-canbus");
            2
        }
    };

    process::exit(exit_code);
}
