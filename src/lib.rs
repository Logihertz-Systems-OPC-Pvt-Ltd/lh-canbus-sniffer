// ==============================================================================
// Product:       Logihertz SocketCAN Real-Time Sniffer (lh-canbus-sniffer)
// Module:        src/lib.rs
// Role:          Root Library Interface (#![forbid(unsafe_code)])
// Organization:  Logihertz Systems (OPC) Private Limited
// Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com / security@logihertz.com
// License:       Apache-2.0
// ==============================================================================

//! Production-grade pure-Rust zero-dependency SocketCAN sniffer, DBC decoder, and security auditor.

#![forbid(unsafe_code)]

pub mod anomaly_detector;
pub mod auditor;
pub mod dbc_decoder;
pub mod exporters;
pub mod json;
