// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        src/auditor.rs
// Role:          10-Rule Deterministic Automotive & Industrial CAN Bus Posture Auditor
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

//! Deterministic CAN bus security posture auditor evaluating 10 normative controls.

use crate::json::JsonValue;

#[derive(Debug, Clone, PartialEq)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: &'static str,
    pub cwe: &'static str,
    pub weight: u32,
    pub description: &'static str,
    pub remediation: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub weight: u32,
    pub cwe: String,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditReport {
    pub manifest_path: String,
    pub score: u32,
    pub status: String,
    pub passed_rules: usize,
    pub total_rules: usize,
    pub findings: Vec<Finding>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

pub struct CanBusAuditor;

impl CanBusAuditor {
    pub fn get_rules() -> Vec<RuleDefinition> {
        vec![
            RuleDefinition {
                id: "LH-CAN-001",
                name: "Disabled AUTOSAR SecOC Authentication or Short MAC",
                severity: "CRITICAL",
                cwe: "CWE-345",
                weight: 25,
                description: "AUTOSAR SecOC CMAC or freshness counter disabled on safety-critical frames, or MAC length < 24 bits.",
                remediation: "Set secoc_authentication_enabled: true and configure secoc_mac_bits >= 24.",
            },
            RuleDefinition {
                id: "LH-CAN-002",
                name: "Unrestricted UDS Flashing or Reset In Motion",
                severity: "CRITICAL",
                cwe: "CWE-284",
                weight: 25,
                description: "Unrestricted UDS firmware flashing (0x34) or ECU reset (0x11) permitted while vehicle/robot is in motion.",
                remediation: "Enable uds_session_guard_in_motion: true and set allow_unauthenticated_uds_0x34: false.",
            },
            RuleDefinition {
                id: "LH-CAN-003",
                name: "Unauthenticated Remote SocketCAN TCP Gateway Exposure",
                severity: "CRITICAL",
                cwe: "CWE-306",
                weight: 25,
                description: "SocketCAN network gateway (socketcand/TCP bridge) bound to external non-loopback network interface.",
                remediation: "Bind SocketCAN TCP gateway strictly to 127.0.0.1 or disable remote bridging.",
            },
            RuleDefinition {
                id: "LH-CAN-004",
                name: "Missing Kernel CAN ID Acceptance Filter Allowlist",
                severity: "HIGH",
                cwe: "CWE-285",
                weight: 10,
                description: "Missing hardware or kernel CAN ID acceptance filter allowlist, permitting unknown arbitration IDs.",
                remediation: "Set can_raw_filter_allowlist_enabled: true and configure unknown_arbitration_id_policy: 'DROP'.",
            },
            RuleDefinition {
                id: "LH-CAN-005",
                name: "Missing Bus-Load Saturation or Dominant ID 0x000 Guard",
                severity: "HIGH",
                cwe: "CWE-400",
                weight: 10,
                description: "Max bus-load threshold exceeds 80.0% or dominant ID 0x000 DoS flood protection is disabled.",
                remediation: "Set max_bus_load_percent <= 80.0 and enable dominant_id_flood_protection: true.",
            },
            RuleDefinition {
                id: "LH-CAN-006",
                name: "Disabled Inter-Arrival Timing Masquerade Detection",
                severity: "HIGH",
                cwe: "CWE-290",
                weight: 10,
                description: "Inter-arrival timing jitter/injection detection disabled or tolerance ratio < 0.25.",
                remediation: "Enable inter_arrival_anomaly_detection: true and set min_interval_tolerance_ratio >= 0.25.",
            },
            RuleDefinition {
                id: "LH-CAN-007",
                name: "Weak UDS 0x27 SecurityAccess Seed Entropy or Missing Lockout",
                severity: "HIGH",
                cwe: "CWE-307",
                weight: 10,
                description: "UDS SecurityAccess (0x27) seed entropy < 128 bits or lockout delay < 10 seconds.",
                remediation: "Set uds_seed_entropy_bits >= 128 and uds_security_access_lockout_seconds >= 10.",
            },
            RuleDefinition {
                id: "LH-CAN-008",
                name: "Missing Gateway Domain Isolation (OBD-II to Powertrain)",
                severity: "MEDIUM",
                cwe: "CWE-693",
                weight: 4,
                description: "Direct bridge between OBD-II/Infotainment and safety Powertrain/ADAS CAN domains.",
                remediation: "Enable gateway_domain_isolation: true and set obd2_direct_bus_access: false.",
            },
            RuleDefinition {
                id: "LH-CAN-009",
                name: "Missing ECU Bus-Off Exponential Backoff or Error Monitoring",
                severity: "MEDIUM",
                cwe: "CWE-755",
                weight: 4,
                description: "ECU bus-off recovery backoff disabled or error-passive frame monitoring disabled.",
                remediation: "Set bus_off_exponential_recovery: true and monitor_error_frames: true.",
            },
            RuleDefinition {
                id: "LH-CAN-010",
                name: "Disabled Strict DLC Length or DBC Physical Range Bounds Check",
                severity: "LOW",
                cwe: "CWE-20",
                weight: 1,
                description: "Strict DLC length verification disabled or DBC physical signal range validation bypassed.",
                remediation: "Enable strict_dlc_validation: true and dbc_signal_bounds_check: true.",
            },
        ]
    }

    pub fn audit_policy(policy: &JsonValue, manifest_path: &str) -> AuditReport {
        let rules = Self::get_rules();
        let mut findings = Vec::new();

        // 1. LH-CAN-001 (CRITICAL, 25)
        let secoc_enabled = policy
            .get("secoc_authentication_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let secoc_bits = policy
            .get("secoc_mac_bits")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if !secoc_enabled || secoc_bits < 24 {
            findings.push(Finding {
                rule_id: rules[0].id.to_string(),
                rule_name: rules[0].name.to_string(),
                severity: rules[0].severity.to_string(),
                weight: rules[0].weight,
                cwe: rules[0].cwe.to_string(),
                message: format!(
                    "secoc_authentication_enabled={}, secoc_mac_bits={} (< 24 bits required).",
                    secoc_enabled, secoc_bits
                ),
                remediation: rules[0].remediation.to_string(),
            });
        }

        // 2. LH-CAN-002 (CRITICAL, 25)
        let uds_guard_in_motion = policy
            .get("uds_session_guard_in_motion")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let allow_unauth_flash = policy
            .get("allow_unauthenticated_uds_0x34")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !uds_guard_in_motion || allow_unauth_flash {
            findings.push(Finding {
                rule_id: rules[1].id.to_string(),
                rule_name: rules[1].name.to_string(),
                severity: rules[1].severity.to_string(),
                weight: rules[1].weight,
                cwe: rules[1].cwe.to_string(),
                message: format!(
                    "uds_session_guard_in_motion={}, allow_unauthenticated_uds_0x34={}.",
                    uds_guard_in_motion, allow_unauth_flash
                ),
                remediation: rules[1].remediation.to_string(),
            });
        }

        // 3. LH-CAN-003 (CRITICAL, 25)
        let tcp_bridge = policy
            .get("socketcan_tcp_bridge_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let bind_addr = policy
            .get("bind_address")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if tcp_bridge && bind_addr != "127.0.0.1" {
            findings.push(Finding {
                rule_id: rules[2].id.to_string(),
                rule_name: rules[2].name.to_string(),
                severity: rules[2].severity.to_string(),
                weight: rules[2].weight,
                cwe: rules[2].cwe.to_string(),
                message: format!(
                    "socketcan_tcp_bridge_enabled=true and bound to external interface '{}'.",
                    bind_addr
                ),
                remediation: rules[2].remediation.to_string(),
            });
        }

        // 4. LH-CAN-004 (HIGH, 10)
        let filter_allowlist = policy
            .get("can_raw_filter_allowlist_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let unknown_policy = policy
            .get("unknown_arbitration_id_policy")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !filter_allowlist || unknown_policy != "DROP" {
            findings.push(Finding {
                rule_id: rules[3].id.to_string(),
                rule_name: rules[3].name.to_string(),
                severity: rules[3].severity.to_string(),
                weight: rules[3].weight,
                cwe: rules[3].cwe.to_string(),
                message: format!(
                    "can_raw_filter_allowlist_enabled={}, unknown_arbitration_id_policy='{}'.",
                    filter_allowlist, unknown_policy
                ),
                remediation: rules[3].remediation.to_string(),
            });
        }

        // 5. LH-CAN-005 (HIGH, 10)
        let max_bus_load = policy
            .get("max_bus_load_percent")
            .and_then(|v| v.as_f64())
            .unwrap_or(100.0);
        let dominant_guard = policy
            .get("dominant_id_flood_protection")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if max_bus_load > 80.0 || !dominant_guard {
            findings.push(Finding {
                rule_id: rules[4].id.to_string(),
                rule_name: rules[4].name.to_string(),
                severity: rules[4].severity.to_string(),
                weight: rules[4].weight,
                cwe: rules[4].cwe.to_string(),
                message: format!(
                    "max_bus_load_percent={:.1}% (> 80.0%), dominant_id_flood_protection={}.",
                    max_bus_load, dominant_guard
                ),
                remediation: rules[4].remediation.to_string(),
            });
        }

        // 6. LH-CAN-006 (HIGH, 10)
        let timing_ids = policy
            .get("inter_arrival_anomaly_detection")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let tol_ratio = policy
            .get("min_interval_tolerance_ratio")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if !timing_ids || tol_ratio < 0.25 {
            findings.push(Finding {
                rule_id: rules[5].id.to_string(),
                rule_name: rules[5].name.to_string(),
                severity: rules[5].severity.to_string(),
                weight: rules[5].weight,
                cwe: rules[5].cwe.to_string(),
                message: format!(
                    "inter_arrival_anomaly_detection={}, min_interval_tolerance_ratio={:.2} (< 0.25).",
                    timing_ids, tol_ratio
                ),
                remediation: rules[5].remediation.to_string(),
            });
        }

        // 7. LH-CAN-007 (HIGH, 10)
        let seed_entropy = policy
            .get("uds_seed_entropy_bits")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let lockout_secs = policy
            .get("uds_security_access_lockout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if seed_entropy < 128 || lockout_secs < 10 {
            findings.push(Finding {
                rule_id: rules[6].id.to_string(),
                rule_name: rules[6].name.to_string(),
                severity: rules[6].severity.to_string(),
                weight: rules[6].weight,
                cwe: rules[6].cwe.to_string(),
                message: format!(
                    "uds_seed_entropy_bits={} (< 128 bits), uds_security_access_lockout_seconds={} (< 10s).",
                    seed_entropy, lockout_secs
                ),
                remediation: rules[6].remediation.to_string(),
            });
        }

        // 8. LH-CAN-008 (MEDIUM, 4)
        let domain_iso = policy
            .get("gateway_domain_isolation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let obd2_direct = policy
            .get("obd2_direct_bus_access")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !domain_iso || obd2_direct {
            findings.push(Finding {
                rule_id: rules[7].id.to_string(),
                rule_name: rules[7].name.to_string(),
                severity: rules[7].severity.to_string(),
                weight: rules[7].weight,
                cwe: rules[7].cwe.to_string(),
                message: format!(
                    "gateway_domain_isolation={}, obd2_direct_bus_access={}.",
                    domain_iso, obd2_direct
                ),
                remediation: rules[7].remediation.to_string(),
            });
        }

        // 9. LH-CAN-009 (MEDIUM, 4)
        let backoff = policy
            .get("bus_off_exponential_recovery")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mon_err = policy
            .get("monitor_error_frames")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !backoff || !mon_err {
            findings.push(Finding {
                rule_id: rules[8].id.to_string(),
                rule_name: rules[8].name.to_string(),
                severity: rules[8].severity.to_string(),
                weight: rules[8].weight,
                cwe: rules[8].cwe.to_string(),
                message: format!(
                    "bus_off_exponential_recovery={}, monitor_error_frames={}.",
                    backoff, mon_err
                ),
                remediation: rules[8].remediation.to_string(),
            });
        }

        // 10. LH-CAN-010 (LOW, 1)
        let dlc_val = policy
            .get("strict_dlc_validation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let bounds_chk = policy
            .get("dbc_signal_bounds_check")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !dlc_val || !bounds_chk {
            findings.push(Finding {
                rule_id: rules[9].id.to_string(),
                rule_name: rules[9].name.to_string(),
                severity: rules[9].severity.to_string(),
                weight: rules[9].weight,
                cwe: rules[9].cwe.to_string(),
                message: format!(
                    "strict_dlc_validation={}, dbc_signal_bounds_check={}.",
                    dlc_val, bounds_chk
                ),
                remediation: rules[9].remediation.to_string(),
            });
        }

        let mut crit = 0;
        let mut high = 0;
        let mut med = 0;
        let mut low = 0;
        let mut deduction = 0;

        for f in &findings {
            deduction += f.weight;
            match f.severity.as_str() {
                "CRITICAL" => crit += 1,
                "HIGH" => high += 1,
                "MEDIUM" => med += 1,
                "LOW" => low += 1,
                _ => {}
            }
        }

        let score = 100_u32.saturating_sub(deduction);
        let status = if score == 100 { "PASSED" } else { "FAILED" };
        let passed = rules.len() - findings.len();

        AuditReport {
            manifest_path: manifest_path.to_string(),
            score,
            status: status.to_string(),
            passed_rules: passed,
            total_rules: rules.len(),
            findings,
            critical_count: crit,
            high_count: high,
            medium_count: med,
            low_count: low,
        }
    }
}
