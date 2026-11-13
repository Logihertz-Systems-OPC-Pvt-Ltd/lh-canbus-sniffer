# Logihertz SocketCAN Real-Time Sniffer & Security Auditor (`lh-canbus`)

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-canbus-sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-canbus-sniffer/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](Cargo.toml)
[![Unsafe Forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](src/lib.rs)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-brightgreen.svg)](Cargo.toml)

**`lh-canbus-sniffer`** (`lh-canbus`) is a production-grade, zero-dependency Rust 2021 automotive & industrial SocketCAN packet sniffer, Vector DBC signal decoder, frame injection anomaly detector, and 10-rule CAN bus security posture auditor.

---

## Key Capabilities

- **100% Zero External Crate Dependencies**: Built entirely with `#![forbid(unsafe_code)]` and the Rust Standard Library (`std`). No external crates (`serde`, `nom`, `byteorder`, etc.).
- **DBC Signal Decoding Engine**: Decodes multi-byte Intel (Little-Endian) and Motorola (Big-Endian) signals from CAN 2.0A/B and CAN-FD payloads with physical scale, offset, and range bounds verification.
- **Bosch CAN 2.0 CRC-15 Validation**: Computes standard 15-bit cyclic redundancy check ($G(x) = x^{15} + x^{14} + x^{10} + x^8 + x^7 + x^4 + x^3 + 1$, polynomial `0x4599`).
- **Real-Time Bus Utilization Modeling ($U_{\text{bus}}$)**: Evaluates wire utilization taking into account 47-bit CAN 2.0A frame overhead and worst-case 20% bit stuffing.
- **Inter-Arrival Spoofing & Injection Detection**: Analyzes per-ID inter-arrival intervals $\Delta t_k$ to detect frame injection anomalies ($\Delta t_k < 0.35 \cdot T_{\text{nom}}$).
- **ISO 14229 UDS Diagnostic Inspection**: Detects unauthorized diagnostic session escalations (`0x10`, `0x11`, `0x27`, `0x28`, `0x2E`, `0x31`, `0x34`) on functional broadcast (`0x7DF`) and physical ECU addresses (`0x7E0..0x7EF`).
- **10-Rule CAN Bus Posture Auditor**: Audits deployment policy manifests against automotive security controls (`LH-CAN-001` through `LH-CAN-010`), exporting findings to ANSI Table, Canonical JSON, and OASIS SARIF v2.1.0.

---

## Mathematical Formulations

### 1. Physical Signal Value Decoding
For raw integer $V_{\text{raw}}$ extracted according to DBC start-bit and length definitions:
$$V_{\text{phys}} = V_{\text{raw}} \cdot \text{scale} + \text{offset}$$
Range boundaries are asserted: $V_{\text{phys}} \in [V_{\min}, V_{\max}]$.

### 2. CAN Bus Utilization ($U_{\text{bus}}$)
Wire frame bits including 47-bit Classic CAN overhead, data bytes $D$, and 20% worst-case bit stuffing:
$$B_{\text{frame}}(D) = \left\lfloor (47 + 8 \cdot D) \cdot 1.20 \right\rfloor$$
$$U_{\text{bus}}(\%) = \frac{\sum_{i=1}^{N} B_{\text{frame}}(D_i)}{R_{\text{bitrate}} \cdot T_{\text{window}}} \times 100.0$$

### 3. Inter-Arrival Masquerade Detection
For consecutive frames with arbitration ID $I$ arriving at timestamps $t_{k-1}$ and $t_k$:
$$\Delta t_k = t_k - t_{k-1}$$
An injection intrusion is flagged when $\Delta t_k < 0.35 \cdot T_{\text{nom}}$, characteristic of an attacker transmitting alongside the legitimate ECU.

### 4. Bosch CAN 2.0 CRC-15 Generator Polynomial
$$G(x) = x^{15} + x^{14} + x^{10} + x^8 + x^7 + x^4 + x^3 + 1 \quad (\text{0x4599})$$

---

## 10-Rule CAN Bus Security Posture Auditor

Policies are evaluated against the standardized posture score:
$$S_{\text{posture}} = \max\left(0, 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

| Rule ID | Severity | Weight | CWE | Control Scope & Remediation |
| :--- | :--- | :---: | :--- | :--- |
| `LH-CAN-001` | CRITICAL | 25 | CWE-345 | Enforces AUTOSAR SecOC CMAC authentication & freshness counters on safety IDs |
| `LH-CAN-002` | CRITICAL | 25 | CWE-284 | Blocks UDS flashing (`0x34`) and ECU reset (`0x11`) while vehicle/robot is in motion |
| `LH-CAN-003` | CRITICAL | 25 | CWE-306 | Prohibits unauthenticated SocketCAN TCP/UDP gateway exposure on external interfaces |
| `LH-CAN-004` | HIGH | 10 | CWE-285 | Mandates kernel CAN raw filter allowlists rejecting unauthorized arbitration IDs |
| `LH-CAN-005` | HIGH | 10 | CWE-400 | Enforces bus-load rate limits ($U_{\text{bus}} \le 80\%$) and dominant `0x000` DoS protection |
| `LH-CAN-006` | HIGH | 10 | CWE-290 | Mandates inter-arrival timing jitter and masquerade frame injection detection |
| `LH-CAN-007` | HIGH | 10 | CWE-307 | Mandates strong UDS `0x27` SecurityAccess seed-key entropy and brute-force lockout |
| `LH-CAN-008` | MEDIUM | 4 | CWE-693 | Enforces gateway domain isolation between OBD-II/Infotainment and Powertrain/ADAS |
| `LH-CAN-009` | MEDIUM | 4 | CWE-755 | Requires ECU Bus-Off exponential backoff and error frame monitoring |
| `LH-CAN-010` | LOW | 1 | CWE-20 | Enforces strict payload DLC length and DBC physical signal bounds verification |

---

## CLI Usage Reference

```bash
# Display help and version
lh-canbus --help
lh-canbus --version

# Audit CAN bus security policy against 10 normative rules
lh-canbus scan fixtures/hardened_canbus_policy.json --format table
lh-canbus scan fixtures/hardened_canbus_policy.json --format json
lh-canbus scan fixtures/vulnerable_canbus_policy.json --format sarif --output audit.sarif

# Decode live or recorded frame using DBC definitions
lh-canbus decode --dbc fixtures/sample_powertrain.dbc --frame 100#1234567890ABCDEF

# Analyze SocketCAN candump log trace for intrusions and bus load
lh-canbus analyze-trace fixtures/sample_candump.log --dbc fixtures/sample_powertrain.dbc --bitrate 500000

# Verify 15-bit Bosch CAN CRC
lh-canbus verify-crc 1234567890ABCDEF
```

---

## Attribution & Governance

- **Organization**: Logihertz Systems (OPC) Private Limited (`https://logihertz.com/`)
- **Creator, Founder, Director & Sole Developer**: Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`)
- **License**: Apache License 2.0
