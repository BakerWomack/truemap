//! Adjudication: deciding which "open" ports are real services.
//!
//! Four independent discriminators, applied in order of how hard they are to fake:
//!
//! 1. **Control match** (new here, and the strongest). The port behaves exactly
//!    like a port on this same host that we know nothing is listening on. Not an
//!    inference — a measurement against a negative control.
//! 2. **Protocol coherence**. A real service answers in a nameable protocol.
//! 3. **Reconnect consistency**. A real service gives the same answer twice; a
//!    randomising fake (portspoof) does not.
//! 4. **Bulk dedup**. One coherent answer appearing on dozens of ports is a single
//!    fake served everywhere, not dozens of services.
//!
//! The ordering matters for honesty: a *silent* port on a discriminating host is
//! reported as open-but-unidentified, not as fake. Degreaser's own Internet-scale
//! finding backs this — a lone half-responder in a subnet was almost always a real
//! service, while hundreds of them meant a tarpit. Scarcity is the signal.

use std::collections::HashMap;
use std::net::IpAddr;

use futures::stream::{self, StreamExt};
use serde::Serialize;

use crate::calib::{Calibration, Posture};
use crate::coherent::Proto;
use crate::probe::{probe, Close, Payload, ProbeCfg, Signature, Spoke};

/// How many ports may share one coherent response before we call it a single fake
/// served everywhere. Carried over from hostscan's `BULK_MIN`.
pub const BULK_MIN: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Verdict {
    /// A real service, named. The only verdict that is evidence of anything.
    Real(Proto),
    /// Handshake succeeded, nothing identifiable, but the host discriminates and
    /// such ports are scarce here — most likely a real service we cannot name.
    OpenUnidentified,
    /// Indistinguishable from a known-closed control port on this host.
    PhantomControlMatch,
    /// Answered, but with nothing that is any protocol, on a host that answers
    /// everything.
    FakeIncoherent,
    /// Coherent but different on every connection — portspoof-style randomiser.
    FakeRandomised,
    /// A coherent response shared by many ports — one fake served everywhere.
    FakeUniform,
    /// Accepted the connection and froze it. LaBrea / netfilter TARPIT shape.
    Tarpit,
    /// Did not complete a handshake during adjudication.
    Closed,
}

impl Verdict {
    pub fn is_real(&self) -> bool {
        matches!(self, Verdict::Real(_) | Verdict::OpenUnidentified)
    }
    pub fn is_fake(&self) -> bool {
        matches!(
            self,
            Verdict::PhantomControlMatch
                | Verdict::FakeIncoherent
                | Verdict::FakeRandomised
                | Verdict::FakeUniform
                | Verdict::Tarpit
        )
    }
    pub fn label(&self) -> String {
        match self {
            Verdict::Real(p) => format!("real:{}", p.name()),
            Verdict::OpenUnidentified => "open-unidentified".into(),
            Verdict::PhantomControlMatch => "phantom(matches-closed-control)".into(),
            Verdict::FakeIncoherent => "fake(no-protocol)".into(),
            Verdict::FakeRandomised => "fake(randomised-banner)".into(),
            Verdict::FakeUniform => "fake(uniform-banner)".into(),
            Verdict::Tarpit => "tarpit(accepted-then-froze)".into(),
            Verdict::Closed => "closed".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortReport {
    pub port: u16,
    pub verdict: Verdict,
    pub why: String,
    pub proto: Option<Proto>,
    pub sample: String,
    pub connect_ms: u64,
}

/// Probe each candidate port twice (two different nudges) and decide.
pub async fn adjudicate(
    ip: IpAddr,
    candidates: &[u16],
    calib: &Calibration,
    cfg: &ProbeCfg,
    concurrency: usize,
) -> Vec<PortReport> {
    // Two passes per port: an HTTP nudge and a TLS nudge. Two connections gives us
    // reconnect-consistency *and* two probe types for the price of both.
    let pairs: Vec<(u16, Signature, Signature)> = stream::iter(candidates.iter().copied().map(
        |port| async move {
            let a = probe(ip, port, Payload::Http, cfg).await;
            let b = probe(ip, port, Payload::Tls, cfg).await;
            (port, a, b)
        },
    ))
    .buffer_unordered(concurrency)
    .collect()
    .await;

    // First pass: per-port verdict, without cross-port knowledge yet.
    let mut staged: Vec<(u16, Signature, Signature, Verdict, String)> = Vec::new();
    #[allow(clippy::type_complexity)]
    for (port, a, b) in pairs {
        let (v, why) = classify_one(&a, &b, calib);
        staged.push((port, a, b, v, why));
    }

    // THIRD PASS, DELIBERATELY NARROW. Only the ports that survived as
    // `OpenUnidentified` get another connection: they completed a handshake, spoke
    // no protocol we know, and did NOT match a known-closed control. That set is
    // small on a discriminating host and EMPTY on an answers-everything one (there,
    // silent ports are already phantom), so this cannot turn a 65535-port blanket
    // scan into 65535 extra connections.
    //
    // Port 53 gets a real DNS query, because a nameserver speaks neither HTTP nor
    // TLS and would otherwise be permanently "open, protocol unknown".
    let third: Vec<usize> = staged
        .iter()
        .enumerate()
        .filter(|(_, (_, _, _, v, _))| matches!(v, Verdict::OpenUnidentified))
        .map(|(i, _)| i)
        .collect();
    if !third.is_empty() {
        let probes: Vec<(usize, Signature)> = stream::iter(third.into_iter().map(|i| {
            let port = staged[i].0;
            async move {
                let payload = if port == 53 || port == 5353 {
                    Payload::Dns
                } else {
                    Payload::Newline
                };
                (i, probe(ip, port, payload, cfg).await)
            }
        }))
        .buffer_unordered(concurrency)
        .collect()
        .await;
        for (i, sig) in probes {
            if let Some(p) = sig.proto {
                staged[i].3 = Verdict::Real(p);
                staged[i].4 = format!(
                    "silent to the HTTP and TLS nudges, but answered {} on a third probe \
                     — a real service that simply speaks neither",
                    p.name()
                );
                staged[i].1 = sig;
            }
        }
    }

    // Second pass: bulk dedup. A coherent response byte-identical across more than
    // BULK_MIN ports is one fake served everywhere. Only coherent survivors are
    // eligible — incoherent ones are already dealt with.
    let mut cluster: HashMap<u64, usize> = HashMap::new();
    for (_, a, _, v, _) in &staged {
        if matches!(v, Verdict::Real(_)) {
            *cluster.entry(a.hash).or_insert(0) += 1;
        }
    }

    let mut out: Vec<PortReport> = staged
        .into_iter()
        .map(|(port, a, _b, mut v, mut why)| {
            if matches!(v, Verdict::Real(_)) {
                let n = cluster.get(&a.hash).copied().unwrap_or(1);
                if n > BULK_MIN {
                    v = Verdict::FakeUniform;
                    why = format!(
                        "byte-identical response on {n} ports — one canned answer served everywhere, \
                         not {n} services"
                    );
                }
            }
            PortReport {
                port,
                verdict: v,
                why,
                proto: a.proto,
                sample: a.sample.clone(),
                connect_ms: a.connect_ms,
            }
        })
        .collect();
    out.sort_by_key(|r| r.port);
    out
}

/// The per-port decision, given both probe passes and the calibration baseline.
pub fn classify_one(a: &Signature, b: &Signature, calib: &Calibration) -> (Verdict, String) {
    if !a.connected && !b.connected {
        return (
            Verdict::Closed,
            "no handshake on either adjudication pass".into(),
        );
    }

    let pa = a.proto;
    let pb = b.proto;

    // (2) Coherent on at least one pass -> candidate real service.
    if let Some(p) = pa.or(pb) {
        // (3) Reconnect consistency. Only meaningful when BOTH passes got a
        // response to compare; a TLS-only port legitimately answers one nudge and
        // not the other, so a one-sided silence is not a randomiser.
        if pa.is_some() && pb.is_some() {
            if pa != pb {
                // Different protocol each time is a randomiser, not a service —
                // unless it is the ordinary http/tls pairing of one web server.
                let web_pair = matches!(
                    (pa, pb),
                    (Some(Proto::Http), Some(Proto::Tls)) | (Some(Proto::Tls), Some(Proto::Http))
                );
                if !web_pair {
                    return (
                        Verdict::FakeRandomised,
                        format!(
                            "answered as {} then {} on two connections — a randomising fake",
                            pa.map(|x| x.name()).unwrap_or("-"),
                            pb.map(|x| x.name()).unwrap_or("-")
                        ),
                    );
                }
            } else if a.hash != b.hash && a.spoke == b.spoke {
                return (
                    Verdict::FakeRandomised,
                    "same protocol but a different banner each connection (digits ignored) — \
                     a randomising fake"
                        .into(),
                );
            }
        }
        return (
            Verdict::Real(p),
            format!("spoke {} — a protocol a fabricated port cannot produce", p.name()),
        );
    }

    // (1) No protocol anywhere. Does it behave like a port we KNOW is closed?
    if calib.is_phantom(a) || calib.is_phantom(b) {
        // When the shape it shares with the controls is specifically the freeze —
        // accepted, swallowed our probe, never spoke, never closed — name the
        // tarpit. Both statements are true; this one is more useful.
        if a.close == Close::HeldOpen && a.spoke == Spoke::Nothing && a.bytes == 0 {
            return (
                Verdict::Tarpit,
                format!(
                    "accepted the connection, swallowed the probe and never answered or closed \
                     — the same freeze as the known-closed control ports {:?}, so this is a \
                     tarpit answering every port, not a service",
                    &calib.control_ports[..calib.control_ports.len().min(3)]
                ),
            );
        }
        return (
            Verdict::PhantomControlMatch,
            format!(
                "behaviour identical to the known-closed control ports {:?} on this host \
                 (connect ok, no protocol, same close behaviour) — fabricated",
                &calib.control_ports[..calib.control_ports.len().min(3)]
            ),
        );
    }

    // Accepted, took our bytes, never spoke, never closed: the tarpit freeze.
    if a.close == Close::HeldOpen && a.spoke == Spoke::Nothing && a.bytes == 0 {
        if matches!(calib.posture, Posture::Blanket) {
            return (
                Verdict::Tarpit,
                "accepted the connection, swallowed the probe and never answered or closed, \
                 on a host that answers every port — tarpit freeze"
                    .into(),
            );
        }
    }

    // Clean EOF with no data: the `tcpwrapped` shape. Real when scarce (a service
    // that refused us), fake when the host answers everything.
    match calib.posture {
        Posture::Blanket => (
            Verdict::FakeIncoherent,
            "handshake succeeded but no protocol on either pass, on a host that answers \
             every port — no evidence of a service"
                .into(),
        ),
        _ => (
            Verdict::OpenUnidentified,
            "handshake succeeded, no protocol identified, but this host refuses closed ports \
             — most likely a real service we cannot name (client-speaks-first, or access denied)"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calib::Posture;

    fn calib(posture: Posture, baseline: Vec<Signature>) -> Calibration {
        Calibration {
            posture,
            controls_probed: 12,
            controls_answered: if matches!(posture, Posture::Blanket) { 12 } else { 0 },
            controls_refused: if matches!(posture, Posture::Blanket) { 0 } else { 12 },
            controls_timed_out: 0,
            control_ports: vec![50001, 50002, 50003],
            baseline,
            rtt_ms: Some(1), l4_promoted: false,
        }
    }

    fn silent_open() -> Signature {
        Signature {
            connected: true, dial: crate::probe::Dial::Connected,
            connect_ms: 1, bytes: 0, hash: crate::coherent::sig_hash(b""),
            proto: None, spoke: Spoke::Nothing, close: Close::HeldOpen, sample: String::new(),
        }
    }

    fn spoke(proto: Proto, body: &[u8], how: Spoke) -> Signature {
        Signature {
            connected: true, dial: crate::probe::Dial::Connected, connect_ms: 1, bytes: body.len(),
            hash: crate::coherent::sig_hash(body), proto: Some(proto),
            spoke: how, close: Close::EofAfterData, sample: String::new(),
        }
    }

    #[test]
    fn a_real_service_survives_on_an_answers_everything_host() {
        let c = calib(Posture::Blanket, vec![silent_open()]);
        let s = spoke(Proto::Ssh, b"SSH-2.0-OpenSSH_9.6p1", Spoke::Greeting);
        let (v, _) = classify_one(&s, &s, &c);
        assert_eq!(v, Verdict::Real(Proto::Ssh));
    }

    /// The SYN-proxy sink shape: handshake completes, nothing is said, connection
    /// closes cleanly. Indistinguishable from a control -> fabricated.
    fn proxy_sink() -> Signature {
        Signature {
            connected: true, dial: crate::probe::Dial::Connected,
            connect_ms: 1, bytes: 0, hash: crate::coherent::sig_hash(b""),
            proto: None, spoke: Spoke::Nothing, close: Close::EofNoData, sample: String::new(),
        }
    }

    #[test]
    fn a_port_behaving_like_a_closed_control_is_phantom() {
        let c = calib(Posture::Blanket, vec![proxy_sink()]);
        let (v, why) = classify_one(&proxy_sink(), &proxy_sink(), &c);
        assert_eq!(v, Verdict::PhantomControlMatch);
        assert!(why.contains("known-closed control"), "why must cite the control: {why}");
    }

    #[test]
    fn the_freeze_shape_is_named_as_a_tarpit_not_just_phantom() {
        // Same evidence, more specific label: accepted, swallowed the probe, never
        // spoke, never closed -- and the controls do it too.
        let c = calib(Posture::Blanket, vec![silent_open()]);
        let (v, why) = classify_one(&silent_open(), &silent_open(), &c);
        assert_eq!(v, Verdict::Tarpit);
        assert!(v.is_fake());
        assert!(why.contains("tarpit"), "why must name the tarpit: {why}");
    }

    #[test]
    fn a_silent_port_on_a_discriminating_host_is_not_called_fake() {
        // The anti-false-negative guard. No calibration baseline exists because
        // closed ports refused, so there is nothing to match against.
        let c = calib(Posture::Discriminating, vec![]);
        let (v, _) = classify_one(&silent_open(), &silent_open(), &c);
        assert_eq!(v, Verdict::OpenUnidentified);
        assert!(v.is_real(), "scarce silent ports must stay in the report");
    }

    #[test]
    fn portspoof_randomised_banners_are_caught() {
        let c = calib(Posture::Blanket, vec![silent_open()]);
        let a = spoke(Proto::SmtpFtp, b"220 fake-abcdefghij ready", Spoke::Greeting);
        let b = spoke(Proto::SmtpFtp, b"220 fake-zyxwvutsrq ready", Spoke::Greeting);
        let (v, _) = classify_one(&a, &b, &c);
        assert_eq!(v, Verdict::FakeRandomised);
    }

    #[test]
    fn a_real_service_with_a_varying_counter_is_not_called_randomised() {
        let c = calib(Posture::Blanket, vec![silent_open()]);
        let a = spoke(Proto::SmtpFtp, b"220 mail ESMTP ready 1699999999", Spoke::Greeting);
        let b = spoke(Proto::SmtpFtp, b"220 mail ESMTP ready 1700000042", Spoke::Greeting);
        let (v, _) = classify_one(&a, &b, &c);
        assert_eq!(v, Verdict::Real(Proto::SmtpFtp), "digits must be ignored");
    }

    #[test]
    fn http_on_one_pass_and_tls_on_the_other_is_one_web_server() {
        let c = calib(Posture::Blanket, vec![silent_open()]);
        let a = spoke(Proto::Http, b"HTTP/1.1 400 Bad Request", Spoke::HttpProbe);
        let b = spoke(Proto::Tls, &[0x16, 0x03, 0x03], Spoke::TlsProbe);
        let (v, _) = classify_one(&a, &b, &c);
        assert!(matches!(v, Verdict::Real(_)), "http+tls pairing is not a randomiser");
    }

    #[tokio::test]
    async fn bulk_identical_coherent_answers_collapse_to_one_fake() {
        // 15 ports all returning the same canned HTTP page.
        let c = calib(Posture::Blanket, vec![silent_open()]);
        let canned = b"HTTP/1.1 200 OK\r\nServer: canned\r\n\r\n";
        let mut cluster: HashMap<u64, usize> = HashMap::new();
        let s = spoke(Proto::Http, canned, Spoke::HttpProbe);
        for _ in 0..15 {
            let (v, _) = classify_one(&s, &s, &c);
            if matches!(v, Verdict::Real(_)) {
                *cluster.entry(s.hash).or_insert(0) += 1;
            }
        }
        assert!(cluster[&s.hash] > BULK_MIN, "the dedup threshold must trip at 15 ports");
    }
}
