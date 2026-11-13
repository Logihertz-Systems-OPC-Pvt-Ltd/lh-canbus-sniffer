# Security Policy

## Supported Versions

Logihertz Systems (OPC) Private Limited maintains and supports the current release of `lh-canbus-sniffer`.

| Version | Supported          | Security Maintenance Status |
| :------ | :----------------- | :-------------------------- |
| 0.1.x   | :white_check_mark: | Active Security Maintenance |
| < 0.1.0 | :x:                | Unsupported / Deprecated    |

## Threat Model & Scope

`lh-canbus-sniffer` inspects, decodes, and audits CAN 2.0A/B and CAN-FD traffic across automotive powertrains, chassis, ADAS, and industrial automation buses. The threat model encompasses:
- Malicious arbitration ID masquerading and frame injection bypassing periodic transmission cadences.
- Dominant-bit arbitration abuse (`0x000`) and high-volume packet injection generating bus-off conditions or Denial-of-Service (DoS) states.
- Unauthorized diagnostic session escalations via ISO 14229 UDS services (`0x10`, `0x11`, `0x27`, `0x28`, `0x2E`, `0x31`, `0x34`) executed during vehicle motion.
- Remote exposure of SocketCAN network gateways (`socketcand`, TCP bridges) without mutual authentication or loopback isolation.
- Disablement of AUTOSAR SecOC (Secure Onboard Communication) MAC verification and freshness counters on safety-critical frame IDs.
- Corrupted signal values breaching physical actuator safety limits (engine RPM, steering angle, brake pressure).

## Reporting a Vulnerability

If you identify a security defect, memory safety issue, or diagnostic intrusion bypass in `lh-canbus-sniffer`, report it directly to the Logihertz security team:

- **Primary Security Contact**: Sameer Tawade (`security@logihertz.com`)
- **Operational Inquiries**: `ops@logihertz.com`
- **PGP Encryption**: Available upon request for sensitive exploit payloads.

Please provide:
1. Detailed description of the vulnerability, affected decoder or detection routines, and safety impact.
2. Reproduction steps including sample `candump` trace or DBC definition files.
3. Target environment details (Linux kernel, SocketCAN interface driver, hardware CAN controller).

## Response & Disclosure SLA

- **Initial Triage & Acknowledgment**: Within 24–48 hours of receipt.
- **Root Cause & Remediation Plan**: Within 5 business days.
- **Security Advisory & Patch Release**: Within 14 calendar days via coordinated release.
