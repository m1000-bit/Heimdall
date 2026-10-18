//! Typed messages exchanged between the two AIs.
//!
//! Encoding is hand-rolled and length-prefixed rather than derived from serde,
//! because this format crosses a trust boundary. A derived format would inherit
//! whatever the serialiser version happened to emit, and a future field addition
//! would then be a silent protocol change rather than an explicit one.
//!
//! Every variant is bounded. `Command` and `PatchRequest` in particular are
//! executed by the peer, so an unbounded string from a compromised or buggy AI
//! must not be able to exhaust the receiver's memory.

use crate::error::{Error, Result};

/// Hard cap on any single string field carried in a message.
pub const MAX_STRING: usize = 64 * 1024;
/// Hard cap on the encoded size of any message.
pub const MAX_MESSAGE: usize = MAX_STRING * 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Sentinel reports a detected threat. Sentinel -> Core.
    ThreatAlert(ThreatAlert),
    /// Sentinel acknowledges a Core directive. Sentinel -> Core.
    Ack { ref_id: u64 },
    /// Sentinel reports its health. Sentinel -> Core.
    Health(HealthReport),
    /// Core issues a natural-language or structured command. Core -> Sentinel.
    Command(Command),
    /// Core asks Sentinel to contain an incident. Core -> Sentinel.
    Contain {
        incident_id: u64,
        scope: ContainmentScope,
    },
    /// Core proposes a self-repair patch. Requires explicit user approval
    /// before anything is applied; see `heimdall_core::gate`.
    PatchProposal(PatchProposal),
    /// Either side closes the session cleanly.
    Close { reason: CloseReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Info),
            1 => Ok(Self::Low),
            2 => Ok(Self::Medium),
            3 => Ok(Self::High),
            4 => Ok(Self::Critical),
            other => Err(Error::Protocol(format!("unknown severity {other}"))),
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatAlert {
    pub alert_id: u64,
    pub severity: Severity,
    pub category: String,
    pub summary: String,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub sentinel_id: String,
    pub uptime_secs: u64,
    pub events_scanned: u64,
    pub active_containments: u32,
    pub engine_load_permille: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub command_id: u64,
    pub intent: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentScope {
    /// Drop traffic to/from a single address.
    Address { cidr: String },
    /// Suspend a specific process by pid.
    Process { pid: u32 },
    /// Disable a network interface.
    Interface { name: String },
    /// Read-only lockdown of the whole node.
    HostQuarantine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchProposal {
    pub proposal_id: u64,
    pub target_path: String,
    pub rationale: String,
    /// Unified diff. Never applied without a matching `Approval`.
    pub diff: String,
    pub generated_by_model: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Shutdown,
    SessionExpired,
    PeerViolation,
    UserRequested,
}

impl CloseReason {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Shutdown),
            1 => Ok(Self::SessionExpired),
            2 => Ok(Self::PeerViolation),
            3 => Ok(Self::UserRequested),
            other => Err(Error::Protocol(format!("unknown close reason {other}"))),
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::Shutdown => 0,
            Self::SessionExpired => 1,
            Self::PeerViolation => 2,
            Self::UserRequested => 3,
        }
    }
}

/// Wire tags. Stable: never reuse a value, only append.
mod tag {
    pub const THREAT_ALERT: u8 = 1;
    pub const ACK: u8 = 2;
    pub const HEALTH: u8 = 3;
    pub const COMMAND: u8 = 4;
    pub const CONTAIN: u8 = 5;
    pub const PATCH_PROPOSAL: u8 = 6;
    pub const CLOSE: u8 = 7;
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        match self {
            Self::ThreatAlert(a) => {
                out.push(tag::THREAT_ALERT);
                out.extend_from_slice(&a.alert_id.to_be_bytes());
                out.push(a.severity.as_u8());
                put_u64(&mut out, a.observed_at_unix);
                put_str(&mut out, &a.category)?;
                put_str(&mut out, &a.summary)?;
            }
            Self::Ack { ref_id } => {
                out.push(tag::ACK);
                out.extend_from_slice(&ref_id.to_be_bytes());
            }
            Self::Health(h) => {
                out.push(tag::HEALTH);
                put_str(&mut out, &h.sentinel_id)?;
                put_u64(&mut out, h.uptime_secs);
                put_u64(&mut out, h.events_scanned);
                out.extend_from_slice(&h.active_containments.to_be_bytes());
                out.extend_from_slice(&h.engine_load_permille.to_be_bytes());
            }
            Self::Command(c) => {
                out.push(tag::COMMAND);
                out.extend_from_slice(&c.command_id.to_be_bytes());
                put_str(&mut out, &c.intent)?;
                put_u32(&mut out, c.arguments.len())?;
                for a in &c.arguments {
                    put_str(&mut out, a)?;
                }
            }
            Self::Contain { incident_id, scope } => {
                out.push(tag::CONTAIN);
                out.extend_from_slice(&incident_id.to_be_bytes());
                match scope {
                    ContainmentScope::Address { cidr } => {
                        out.push(0);
                        put_str(&mut out, cidr)?;
                    }
                    ContainmentScope::Process { pid } => {
                        out.push(1);
                        out.extend_from_slice(&pid.to_be_bytes());
                    }
                    ContainmentScope::Interface { name } => {
                        out.push(2);
                        put_str(&mut out, name)?;
                    }
                    ContainmentScope::HostQuarantine => {
                        out.push(3);
                    }
                }
            }
            Self::PatchProposal(p) => {
                out.push(tag::PATCH_PROPOSAL);
                out.extend_from_slice(&p.proposal_id.to_be_bytes());
                put_str(&mut out, &p.target_path)?;
                put_str(&mut out, &p.rationale)?;
                put_str(&mut out, &p.diff)?;
                put_str(&mut out, &p.generated_by_model)?;
            }
            Self::Close { reason } => {
                out.push(tag::CLOSE);
                out.push(reason.as_u8());
            }
        }

        if out.len() > MAX_MESSAGE {
            return Err(Error::Protocol(format!(
                "encoded message is {} bytes, over the {MAX_MESSAGE} limit",
                out.len()
            )));
        }
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(Error::Protocol("empty message".into()));
        }
        if buf.len() > MAX_MESSAGE {
            return Err(Error::Protocol("message exceeds the size limit".into()));
        }
        let mut c = Cursor::new(buf);
        let tag = c.u8()?;
        match tag {
            tag::THREAT_ALERT => Ok(Self::ThreatAlert(ThreatAlert {
                alert_id: c.u64()?,
                severity: Severity::from_u8(c.u8()?)?,
                observed_at_unix: c.u64()?,
                category: c.string()?,
                summary: c.string()?,
            })),
            tag::ACK => Ok(Self::Ack { ref_id: c.u64()? }),
            tag::HEALTH => Ok(Self::Health(HealthReport {
                sentinel_id: c.string()?,
                uptime_secs: c.u64()?,
                events_scanned: c.u64()?,
                active_containments: c.u32()?,
                engine_load_permille: c.u16()?,
            })),
            tag::COMMAND => {
                let command_id = c.u64()?;
                let intent = c.string()?;
                let n = c.u32()?;
                let mut arguments = Vec::with_capacity((n as usize).min(64));
                for _ in 0..n {
                    arguments.push(c.string()?);
                }
                Ok(Self::Command(Command {
                    command_id,
                    intent,
                    arguments,
                }))
            }
            tag::CONTAIN => {
                let incident_id = c.u64()?;
                let scope = match c.u8()? {
                    0 => ContainmentScope::Address { cidr: c.string()? },
                    1 => ContainmentScope::Process { pid: c.u32()? },
                    2 => ContainmentScope::Interface { name: c.string()? },
                    3 => ContainmentScope::HostQuarantine,
                    other => {
                        return Err(Error::Protocol(format!(
                            "unknown containment scope {other}"
                        )));
                    }
                };
                Ok(Self::Contain { incident_id, scope })
            }
            tag::PATCH_PROPOSAL => Ok(Self::PatchProposal(PatchProposal {
                proposal_id: c.u64()?,
                target_path: c.string()?,
                rationale: c.string()?,
                diff: c.string()?,
                generated_by_model: c.string()?,
            })),
            tag::CLOSE => Ok(Self::Close {
                reason: CloseReason::from_u8(c.u8()?)?,
            }),
            other => Err(Error::Protocol(format!("unknown message tag {other}"))),
        }
    }
}

fn put_u32(out: &mut Vec<u8>, v: usize) -> Result<()> {
    let v = u32::try_from(v).map_err(|_| Error::Protocol("field count too large".into()))?;
    out.extend_from_slice(&v.to_be_bytes());
    Ok(())
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<()> {
    if s.len() > MAX_STRING {
        return Err(Error::Protocol(format!(
            "string field is {} bytes, over the {MAX_STRING} limit",
            s.len()
        )));
    }
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Bounds-checked reader. Every accessor validates that the input still has the
/// bytes it needs, so a truncated or hostile buffer produces a clean protocol
/// error instead of a panic.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::Protocol("length overflow".into()))?;
        if end > self.buf.len() {
            return Err(Error::Protocol("truncated message".into()));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        if len > MAX_STRING {
            return Err(Error::Protocol(format!(
                "declared string length {len} exceeds the {MAX_STRING} limit"
            )));
        }
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Protocol("string is not UTF-8".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Message> {
        vec![
            Message::ThreatAlert(ThreatAlert {
                alert_id: 7,
                severity: Severity::Critical,
                category: "network".into(),
                summary: "beaconing to known C2".into(),
                observed_at_unix: 1_700_000_000,
            }),
            Message::Ack { ref_id: 42 },
            Message::Health(HealthReport {
                sentinel_id: "sentinel-01".into(),
                uptime_secs: 999,
                events_scanned: 123_456,
                active_containments: 2,
                engine_load_permille: 137,
            }),
            Message::Command(Command {
                command_id: 1,
                intent: "scan".into(),
                arguments: vec!["/etc/shadow".into(), "--deep".into()],
            }),
            Message::Contain {
                incident_id: 9,
                scope: ContainmentScope::Address {
                    cidr: "203.0.113.7/32".into(),
                },
            },
            Message::Contain {
                incident_id: 10,
                scope: ContainmentScope::Process { pid: 4242 },
            },
            Message::Contain {
                incident_id: 11,
                scope: ContainmentScope::Interface {
                    name: "eth0".into(),
                },
            },
            Message::Contain {
                incident_id: 12,
                scope: ContainmentScope::HostQuarantine,
            },
            Message::PatchProposal(PatchProposal {
                proposal_id: 3,
                target_path: "crates/heimdall-core/src/lib.rs".into(),
                rationale: "fix off-by-one in record length check".into(),
                diff: "@@ -1 +1 @@\n-a\n+b".into(),
                generated_by_model: "heimdall-core/self-repair".into(),
            }),
            Message::Close {
                reason: CloseReason::Shutdown,
            },
        ]
    }

    #[test]
    fn every_variant_roundtrips() {
        for m in samples() {
            let bytes = m.encode().unwrap();
            assert_eq!(Message::decode(&bytes).unwrap(), m, "{m:?}");
        }
    }

    #[test]
    fn truncation_at_every_offset_is_rejected_not_panicking() {
        for m in samples() {
            let bytes = m.encode().unwrap();
            for n in 0..bytes.len() {
                // Either a clean protocol error, or it happens to decode to a
                // different message -- what must never happen is a panic.
                let _ = Message::decode(&bytes[..n]);
            }
        }
    }

    #[test]
    fn every_single_bit_flip_never_panics() {
        for m in samples() {
            let bytes = m.encode().unwrap();
            for i in 0..bytes.len().min(48) {
                for bit in 0..8 {
                    let mut bad = bytes.clone();
                    bad[i] ^= 1 << bit;
                    let _ = Message::decode(&bad);
                }
            }
        }
    }

    #[test]
    fn unknown_tag_is_rejected() {
        assert!(Message::decode(&[0xff]).is_err());
        assert!(Message::decode(&[]).is_err());
    }

    #[test]
    fn oversized_string_is_refused_at_encode() {
        let m = Message::Ack { ref_id: 1 };
        assert!(m.encode().is_ok());

        let huge = Message::Command(Command {
            command_id: 1,
            intent: "x".repeat(MAX_STRING + 1),
            arguments: vec![],
        });
        assert!(huge.encode().is_err());
    }

    #[test]
    fn declared_string_length_is_bounded_at_decode() {
        // Announce a 4 GiB string with no payload: must not allocate.
        let mut buf = vec![tag::THREAT_ALERT];
        buf.extend_from_slice(&1u64.to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        assert!(Message::decode(&buf).is_err());
    }

    #[test]
    fn non_utf8_string_is_rejected() {
        let mut buf = vec![tag::THREAT_ALERT];
        buf.extend_from_slice(&1u64.to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&[0xff, 0xfe]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        assert!(Message::decode(&buf).is_err());
    }

    #[test]
    fn severity_ordering_is_escalation_order() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
