# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-041`  
**Repository**: `lh-canbus-sniffer`  
**CLI Executable**: `lh-canbus`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-041` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-canbus-sniffer` (`lh-canbus`) |
| **Target Language / Platform** | `Rust` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-canbus-sniffer](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-canbus-sniffer) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-canbus` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `Rust`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: Bosch CAN 2.0B CRC-15 Cyclic Redundancy Polynomial

The underlying computational core of `lh-canbus-sniffer` is formally governed by the following mathematical and algorithmic formulations:

$$G(x) = x^{15} + x^{14} + x^{10} + x^8 + x^7 + x^4 + x^3 + 1 \quad (\texttt{0x4599})$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-CAN-001` | `CRITICAL` | `25` | `CWE-345` | CWE-345 | Enforces AUTOSAR SecOC CMAC authentication & freshness counters on safety IDs |
| `LH-CAN-002` | `CRITICAL` | `25` | `CWE-284` | CWE-284 | Blocks UDS flashing (0x34) and ECU reset (0x11) while vehicle/robot is in motion |
| `LH-CAN-003` | `CRITICAL` | `25` | `CWE-306` | CWE-306 | Prohibits unauthenticated SocketCAN TCP/UDP gateway exposure on external interfaces |
| `LH-CAN-004` | `HIGH` | `10` | `CWE-285` | CWE-285 | Mandates kernel CAN raw filter allowlists rejecting unauthorized arbitration IDs |
| `LH-CAN-005` | `HIGH` | `10` | `CWE-400` | CWE-400 | Enforces bus-load rate limits ($U_{\text{bus}} \le 80\%$) and dominant 0x000 DoS protection |
| `LH-CAN-006` | `HIGH` | `10` | `CWE-290` | CWE-290 | Mandates inter-arrival timing jitter and masquerade frame injection detection |
| `LH-CAN-007` | `HIGH` | `10` | `CWE-307` | CWE-307 | Mandates strong UDS 0x27 SecurityAccess seed-key entropy and brute-force lockout |
| `LH-CAN-008` | `MEDIUM` | `4` | `CWE-693` | CWE-693 | Enforces gateway domain isolation between OBD-II/Infotainment and Powertrain/ADAS |
| `LH-CAN-009` | `MEDIUM` | `4` | `CWE-755` | CWE-755 | Requires ECU Bus-Off exponential backoff and error frame monitoring |
| `LH-CAN-010` | `LOW` | `1` | `CWE-20` | CWE-20 | Enforces strict payload DLC length and DBC physical signal bounds verification |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-canbus` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-canbus <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-CAN-001` .. `LH-CAN-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## 6. Standalone Future Development Roadmap (`v0.2.0` — `v0.5.0`)

`lh-canbus-sniffer` is developed as an independent, standalone open-source project. The following roadmap defines the planned architectural, algorithmic, and protocol enhancements for upcoming point releases of `lh-canbus-sniffer`:

| Target Release | Milestone Focus | Planned Technical Deliverables for `lh-canbus-sniffer` |
|---|---|---|
| **`v0.2.0`** | Parser & Protocol Expansion | Add multiplexed DBC signal decoding (m0/M), SAE J1939 29-bit Parameter Group Number (PGN / SPN) decoding, and CAN-FD 64-byte frame support. |
| **`v0.3.0`** | Deep Algorithmic & Stateful Analysis | Implement ISO-TP (ISO 15765-2) multi-frame First/Consecutive/FlowControl reassembly for full UDS diagnostic payload inspection. |
| **`v0.4.0`** | Remediation, Synthesis & Format Interop | Add AUTOSAR SecOC (Secure Onboard Communication) truncated AES-CMAC and Freshness Value (FV) verification alongside ECU clock-skew fingerprinting. |
| **`v0.5.0`** | High-Throughput Performance & Formal Verification | Implement native Linux AF_CAN (SOCK_RAW) live SocketCAN capture and PCAPNG (LINKTYPE_CAN_SOCKETCAN) trace export. |

### 6.1 `v0.2.0` — Parser & Protocol Expansion
- **Format & Protocol Ingestion**: Add multiplexed DBC signal decoding (m0/M), SAE J1939 29-bit Parameter Group Number (PGN / SPN) decoding, and CAN-FD 64-byte frame support.
- **Zero-Dependency Architecture**: Pure standard library implementation with deterministic parsing guarantees and strict error handling.
- **Verification & Telemetry**: Regression test suites verifying schema edge-cases, malformed payload rejections, and SARIF v2.1.0 output fidelity.

### 6.2 `v0.3.0` — Deep Algorithmic & Stateful Analysis
- **Algorithmic Core**: Implement ISO-TP (ISO 15765-2) multi-frame First/Consecutive/FlowControl reassembly for full UDS diagnostic payload inspection.
- **State Machine & Analysis Engine**: High-fidelity state tracking, cycle detection, and invariant checking with minimal computational overhead.
- **Differential & Regression Verification**: Comprehensive test harnesses covering stateful transitions, edge conditions, and mathematical boundary constraints.

### 6.3 `v0.4.0` — Remediation, Synthesis & Format Interoperability
- **Synthesis & Interoperability**: Add AUTOSAR SecOC (Secure Onboard Communication) truncated AES-CMAC and Freshness Value (FV) verification alongside ECU clock-skew fingerprinting.
- **Automated Remediation Workflows**: Idempotent generation of verified configuration patches, policy rules, and standardized cross-format exports.
- **Contract & Artifact Validation**: Cryptographic baseline verification and end-to-end integration testing for synthesized deliverables.

### 6.4 `v0.5.0` — High-Throughput Performance & Formal Verification
- **High-Throughput Optimization**: Implement native Linux AF_CAN (SOCK_RAW) live SocketCAN capture and PCAPNG (LINKTYPE_CAN_SOCKETCAN) trace export.
- **Hardware & Kernel Acceleration**: Vectorized SIMD/eBPF/sub-millisecond streaming execution with bounded memory allocation.
- **Formal Verification & Assurance**: Mathematical proof of invariant preservation, false-positive calibration, and high-assurance certification baselines.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
