# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **Pure-Rust Zero-Dependency SocketCAN & DBC Signal Engine**:
  - Classic CAN 2.0A (11-bit), CAN 2.0B (29-bit extended), and CAN-FD frame parsing.
  - Parsing of standard Linux `candump` log files (`(<timestamp>) <iface> <id>#<payload>`).
  - Vector DBC database parser supporting `BO_` messages and `SG_` signals.
  - Multi-byte Intel (Little-Endian) and Motorola (Big-Endian) arbitrary-width bitfield signal extraction ($1 \le L \le 64$ bits).
  - Physical engineering unit conversion ($V_{\text{phys}} = V_{\text{raw}} \cdot \text{scale} + \text{offset}$) with out-of-bounds safety clipping.
  - Bosch CAN 2.0 CRC-15 (`0x4599`) generator polynomial implementation.
- **Automotive Intrusion Detection System (IDS) Engine**:
  - Real-time bus-load utilization modeling ($U_{\text{bus}}$) accounting for 47-bit CAN frame overhead and 20% bit-stuffing overhead.
  - Inter-arrival timing masquerade detection flagging injected periodic frames when $\Delta t_k < 0.35 \cdot T_{\text{nom}}$.
  - ISO 14229 Unified Diagnostic Services (UDS) deep inspection on `0x7DF` and `0x7E0..0x7EF` detecting unauthorized diagnostic requests (`0x10`, `0x11`, `0x27`, `0x28`, `0x2E`, `0x31`, `0x34`).
- **10-Rule CAN Bus Security Posture Auditor**:
  - Automated evaluation of `LH-CAN-001` through `LH-CAN-010`.
  - ANSI Box Table, Canonical JSON, and OASIS SARIF v2.1.0 exporters.
- **Standalone High-Performance CLI Tooling (`lh-canbus`)**:
  - Subcommands: `scan`, `decode`, `analyze-trace`, `verify-crc`, `--version`, and `--help`.
- **Test Suite**:
  - 65+ deterministic test cases and 95+ unit/integration assertions with 100% pass rate.
