# Contributing to Logihertz SocketCAN Sniffer & Auditor

Thank you for contributing to **`lh-canbus-sniffer`** (`lh-canbus`), an open-source tool by Logihertz Systems (OPC) Private Limited.

## Core Mandates & Technical Rules

1. **Strictly `#![forbid(unsafe_code)]`**:
   The entire crate enforces `#![forbid(unsafe_code)]` in both library and binary targets. No `unsafe` blocks are allowed under any circumstances.
2. **Zero External Crate Dependencies**:
   `[dependencies]` in `Cargo.toml` must remain strictly empty. All SocketCAN parsing, DBC decoding, bit extraction, CRC-15 calculation, inter-arrival timing, JSON serialization, and SARIF generation must utilize only the Rust Standard Library (`std`).
3. **Deterministic DBC Bit Extraction & Physical Scaling**:
   - Intel (Little-Endian) bit-fields (`@1`): bit 0 is LSB, spanning across contiguous ascending byte addresses.
   - Motorola (Big-Endian) bit-fields (`@0`): bit numbering follows standard automotive Vector/CANdb convention where bit 7 is MSB of byte 0, crossing byte boundaries down into byte 1 MSB.
   - Physical conversion: $V_{\text{phys}} = V_{\text{raw}} \cdot \text{scale} + \text{offset}$ with boundary validation $V_{\text{phys}} \in [V_{\min}, V_{\max}]$.
4. **Bosch CAN 2.0 CRC-15 Math**:
   Implement standard polynomial $G(x) = x^{15} + x^{14} + x^{10} + x^8 + x^7 + x^4 + x^3 + 1$ (`0x4599`).
5. **Deterministic Posture Auditor Rules**:
   All security checks must adhere to the 10-rule normative taxonomy (`LH-CAN-001` through `LH-CAN-010`), providing assigned CWEs, severities, deduction weights, and actionable remediations.

## Development & Verification Workflow

1. **Format Code**:
   ```bash
   cargo fmt --check
   ```

2. **Run Linter with Zero Warnings**:
   ```bash
   cargo clippy --all-targets -- -D warnings
   ```

3. **Run Comprehensive Test Suite**:
   ```bash
   cargo test --verbose
   ```

4. **Contribution Guidelines**:
   - Write clear conventional commit messages: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`.
   - All commits must acknowledge author attribution to Sameer Tawade (`ops@logihertz.com`) and Logihertz Systems (OPC) Private Limited.
