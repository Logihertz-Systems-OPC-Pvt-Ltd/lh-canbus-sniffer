// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        src/exporters.rs
// Role:          ANSI Table, Canonical JSON, and OASIS SARIF v2.1.0 Exporters
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

//! Exporters for CAN bus posture audit reports.

use crate::auditor::{AuditReport, CanBusAuditor};
use crate::json::JsonValue;

pub struct Exporters;

impl Exporters {
    pub fn format_table(report: &AuditReport) -> String {
        let mut out = String::new();
        out.push('\n');
        out.push_str(&"=".repeat(80));
        out.push('\n');
        out.push_str("   Logihertz SocketCAN Security Posture Auditor (lh-canbus)\n");
        out.push_str(&format!(
            "   Policy Manifest: {}\n",
            if report.manifest_path.is_empty() {
                "In-Memory / Direct Input"
            } else {
                &report.manifest_path
            }
        ));
        out.push_str(&format!(
            "   Posture Score:   {}/100   [{}]\n",
            report.score, report.status
        ));
        out.push_str(&format!(
            "   Summary:         {} passed, {} violations (CRIT: {}, HIGH: {}, MED: {}, LOW: {})\n",
            report.passed_rules,
            report.findings.len(),
            report.critical_count,
            report.high_count,
            report.medium_count,
            report.low_count
        ));
        out.push_str(&"=".repeat(80));
        out.push_str("\n\n");

        if report.findings.is_empty() {
            out.push_str(
                " [OK] All 10 automotive & industrial CAN bus security controls are satisfied.\n",
            );
            out.push_str("      Bus controller configuration conforms to production-grade sovereign standards.\n\n");
            return out;
        }

        let col_fmt = "+----------------+----------+--------+----------+--------------------------------------+";
        let header  = "| Rule ID        | Severity | Weight | CWE      | Rule Title                           |";
        out.push_str(col_fmt);
        out.push('\n');
        out.push_str(header);
        out.push('\n');
        out.push_str(col_fmt);
        out.push('\n');

        for f in &report.findings {
            let short_name = if f.rule_name.len() <= 36 {
                format!("{:<36}", f.rule_name)
            } else {
                format!("{:<33}...", &f.rule_name[..33])
            };

            out.push_str(&format!(
                "| {:<14} | {:<8} | {:<6} | {:<8} | {} |\n",
                f.rule_id, f.severity, f.weight, f.cwe, short_name
            ));

            let msg_sub = if f.message.len() <= 66 {
                format!("{:<66}", f.message)
            } else {
                format!("{:<63}...", &f.message[..63])
            };
            out.push_str(&format!("|   -> Finding:  {} |\n", msg_sub));

            let rem_sub = if f.remediation.len() <= 66 {
                format!("{:<66}", f.remediation)
            } else {
                format!("{:<63}...", &f.remediation[..63])
            };
            out.push_str(&format!("|   -> Action:   {} |\n", rem_sub));
            out.push_str(col_fmt);
            out.push('\n');
        }

        out.push('\n');
        out
    }

    pub fn format_json(report: &AuditReport) -> String {
        let findings_json: Vec<JsonValue> = report
            .findings
            .iter()
            .map(|f| {
                JsonValue::Object(vec![
                    ("rule_id".to_string(), JsonValue::String(f.rule_id.clone())),
                    (
                        "rule_name".to_string(),
                        JsonValue::String(f.rule_name.clone()),
                    ),
                    (
                        "severity".to_string(),
                        JsonValue::String(f.severity.clone()),
                    ),
                    ("weight".to_string(), JsonValue::Number(f.weight as f64)),
                    ("cwe".to_string(), JsonValue::String(f.cwe.clone())),
                    ("message".to_string(), JsonValue::String(f.message.clone())),
                    (
                        "remediation".to_string(),
                        JsonValue::String(f.remediation.clone()),
                    ),
                ])
            })
            .collect();

        let root = JsonValue::Object(vec![
            (
                "version".to_string(),
                JsonValue::String("0.1.0".to_string()),
            ),
            (
                "scanner".to_string(),
                JsonValue::String("lh-canbus".to_string()),
            ),
            (
                "organization".to_string(),
                JsonValue::String("Logihertz Systems (OPC) Private Limited".to_string()),
            ),
            (
                "developer".to_string(),
                JsonValue::String("Sameer Tawade".to_string()),
            ),
            (
                "manifest_path".to_string(),
                JsonValue::String(report.manifest_path.clone()),
            ),
            ("score".to_string(), JsonValue::Number(report.score as f64)),
            (
                "status".to_string(),
                JsonValue::String(report.status.clone()),
            ),
            (
                "total_rules".to_string(),
                JsonValue::Number(report.total_rules as f64),
            ),
            (
                "passed_rules".to_string(),
                JsonValue::Number(report.passed_rules as f64),
            ),
            (
                "severity_counts".to_string(),
                JsonValue::Object(vec![
                    (
                        "critical".to_string(),
                        JsonValue::Number(report.critical_count as f64),
                    ),
                    (
                        "high".to_string(),
                        JsonValue::Number(report.high_count as f64),
                    ),
                    (
                        "medium".to_string(),
                        JsonValue::Number(report.medium_count as f64),
                    ),
                    (
                        "low".to_string(),
                        JsonValue::Number(report.low_count as f64),
                    ),
                ]),
            ),
            ("findings".to_string(), JsonValue::Array(findings_json)),
        ]);

        root.serialize()
    }

    pub fn format_sarif(report: &AuditReport) -> String {
        let rules_json: Vec<JsonValue> = CanBusAuditor::get_rules()
            .iter()
            .map(|r| {
                JsonValue::Object(vec![
                    ("id".to_string(), JsonValue::String(r.id.to_string())),
                    ("name".to_string(), JsonValue::String(r.name.to_string())),
                    (
                        "shortDescription".to_string(),
                        JsonValue::Object(vec![(
                            "text".to_string(),
                            JsonValue::String(r.name.to_string()),
                        )]),
                    ),
                    (
                        "fullDescription".to_string(),
                        JsonValue::Object(vec![(
                            "text".to_string(),
                            JsonValue::String(r.description.to_string()),
                        )]),
                    ),
                    (
                        "help".to_string(),
                        JsonValue::Object(vec![(
                            "text".to_string(),
                            JsonValue::String(r.remediation.to_string()),
                        )]),
                    ),
                    (
                        "properties".to_string(),
                        JsonValue::Object(vec![
                            (
                                "tags".to_string(),
                                JsonValue::Array(vec![
                                    JsonValue::String("automotive".to_string()),
                                    JsonValue::String("canbus".to_string()),
                                    JsonValue::String("security".to_string()),
                                    JsonValue::String(r.cwe.to_lowercase()),
                                ]),
                            ),
                            (
                                "precision".to_string(),
                                JsonValue::String("high".to_string()),
                            ),
                            (
                                "problem.severity".to_string(),
                                JsonValue::String(
                                    if r.severity == "CRITICAL" || r.severity == "HIGH" {
                                        "error".to_string()
                                    } else {
                                        "warning".to_string()
                                    },
                                ),
                            ),
                            (
                                "security-severity".to_string(),
                                JsonValue::String(if r.severity == "CRITICAL" {
                                    "9.0".to_string()
                                } else if r.severity == "HIGH" {
                                    "7.0".to_string()
                                } else {
                                    "4.0".to_string()
                                }),
                            ),
                        ]),
                    ),
                ])
            })
            .collect();

        let results_json: Vec<JsonValue> = report
            .findings
            .iter()
            .map(|f| {
                let level = if f.severity == "CRITICAL" || f.severity == "HIGH" {
                    "error"
                } else {
                    "warning"
                };

                JsonValue::Object(vec![
                    ("ruleId".to_string(), JsonValue::String(f.rule_id.clone())),
                    ("level".to_string(), JsonValue::String(level.to_string())),
                    (
                        "message".to_string(),
                        JsonValue::Object(vec![(
                            "text".to_string(),
                            JsonValue::String(format!(
                                "{}: {} Remediation: {}",
                                f.rule_name, f.message, f.remediation
                            )),
                        )]),
                    ),
                    (
                        "locations".to_string(),
                        JsonValue::Array(vec![JsonValue::Object(vec![(
                            "physicalLocation".to_string(),
                            JsonValue::Object(vec![(
                                "artifactLocation".to_string(),
                                JsonValue::Object(vec![(
                                    "uri".to_string(),
                                    JsonValue::String(if report.manifest_path.is_empty() {
                                        "policy.json".to_string()
                                    } else {
                                        report.manifest_path.clone()
                                    }),
                                )]),
                            )]),
                        )])]),
                    ),
                    (
                        "properties".to_string(),
                        JsonValue::Object(vec![
                            ("cwe".to_string(), JsonValue::String(f.cwe.clone())),
                            (
                                "severity".to_string(),
                                JsonValue::String(f.severity.clone()),
                            ),
                            ("weight".to_string(), JsonValue::Number(f.weight as f64)),
                        ]),
                    ),
                ])
            })
            .collect();

        let root = JsonValue::Object(vec![
            ("$schema".to_string(), JsonValue::String("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string())),
            ("version".to_string(), JsonValue::String("2.1.0".to_string())),
            ("runs".to_string(), JsonValue::Array(vec![
                JsonValue::Object(vec![
                    ("tool".to_string(), JsonValue::Object(vec![
                        ("driver".to_string(), JsonValue::Object(vec![
                            ("name".to_string(), JsonValue::String("lh-canbus".to_string())),
                            ("semanticVersion".to_string(), JsonValue::String("0.1.0".to_string())),
                            ("informationUri".to_string(), JsonValue::String("https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-canbus-sniffer".to_string())),
                            ("organization".to_string(), JsonValue::String("Logihertz Systems (OPC) Private Limited".to_string())),
                            ("rules".to_string(), JsonValue::Array(rules_json)),
                        ])),
                    ])),
                    ("results".to_string(), JsonValue::Array(results_json)),
                ]),
            ])),
        ]);

        root.serialize()
    }
}
