//! Host liveness: is anything actually there?
//!
//! The question the port list cannot answer on its own. A host behind a SYN proxy
//! shows 65535 open ports and may have nothing behind it; a host behind a strict
//! firewall shows nothing and may be running a dozen services.
//!
//! So liveness is decided by *evidence*, not by port count:
//!
//!   * one named protocol anywhere  -> ALIVE, and we can say what proved it
//!   * answers every port, nothing named -> something is on the path (the proxy
//!     itself), but no service was proven. Reported as OPAQUE, not as "65535 open".
//!   * nothing answered -> DEAD or filtered, and we say which by whether closed
//!     ports refused (reachable) or timed out (dropped).

use serde::Serialize;

use crate::adjudicate::{PortReport, Verdict};
use crate::calib::{Calibration, Posture};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Liveness {
    /// A real service was identified. The host is up and reachable, proven.
    AliveConfirmed,
    /// Real services exist AND the host fabricates open ports. Both are true.
    AliveDeceptive,
    /// The host (or a middlebox in front of it) completes handshakes, but not one
    /// port could be shown to run a service. Up at layer 4, opaque above it.
    AliveOpaque,
    /// Closed ports are actively REFUSED, so the host is provably reachable, but no
    /// port in the scanned range runs anything.
    ReachableNoServices,
    /// Nothing answered and nothing refused — every probe was dropped.
    NoResponse,
}

impl Liveness {
    pub fn label(self) -> &'static str {
        match self {
            Liveness::AliveConfirmed => "ALIVE (service confirmed)",
            Liveness::AliveDeceptive => "ALIVE (service confirmed, host fabricates open ports)",
            Liveness::AliveOpaque => "ALIVE-OPAQUE (answers at TCP, no service provable)",
            Liveness::ReachableNoServices => "ALIVE (reachable, no services in range)",
            Liveness::NoResponse => "NO RESPONSE (all probes dropped)",
        }
    }

    /// Is the host demonstrably reachable? Used for the `Status: Up` / `state="up"`
    /// field in the nmap-shaped outputs.
    ///
    /// `AliveOpaque` counts as up: nothing could be PROVED to run there, but the
    /// handshakes completed, so something at that address is answering. Only
    /// `NoResponse` is false, and it means undetermined rather than down -- every
    /// probe was dropped, which a dead host and a silent firewall produce alike.
    pub fn is_up(self) -> bool {
        !matches!(self, Liveness::NoResponse)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostVerdict {
    pub liveness: Liveness,
    /// The ports whose real protocol proves the host is alive. This is the
    /// "known-good port" evidence: a web or ssh port that genuinely answered.
    pub proof: Vec<(u16, String)>,
    pub real_count: usize,
    pub fake_count: usize,
    pub reasoning: String,
}

pub fn decide(reports: &[PortReport], calib: &Calibration) -> HostVerdict {
    let proof: Vec<(u16, String)> = reports
        .iter()
        .filter_map(|r| match &r.verdict {
            Verdict::Real(p) => Some((r.port, p.name().to_string())),
            _ => None,
        })
        .collect();

    let real_count = reports.iter().filter(|r| r.verdict.is_real()).count();
    let fake_count = reports.iter().filter(|r| r.verdict.is_fake()).count();
    let blanket = matches!(calib.posture, Posture::Blanket | Posture::Flaky);

    let (liveness, reasoning) = if !proof.is_empty() {
        let names: Vec<String> = proof
            .iter()
            .take(4)
            .map(|(p, n)| format!("{p}/{n}"))
            .collect();
        if blanket {
            (
                Liveness::AliveDeceptive,
                format!(
                    "{} answered a real protocol, so the host is up — but {} of its control ports \
                     answered too, so the other {fake_count} \"open\" ports are fabricated and are \
                     not reported as services.",
                    names.join(", "),
                    calib.controls_answered
                ),
            )
        } else {
            // The wording must match what was actually measured. This used to assert
            // "closed ports are refused" unconditionally, which was simply false on a
            // host that drops them -- and a report that states a measurement it did
            // not take is worse than one that says less.
            let how = if calib.controls_refused > 0 {
                format!(
                    "Closed ports on this host are actively refused ({} of {} control ports), so \
                     the port list is trustworthy as it stands.",
                    calib.controls_refused, calib.controls_probed
                )
            } else if calib.controls_timed_out > 0 {
                format!(
                    "Closed ports on this host are silently DROPPED, not refused ({} of {} control \
                     ports timed out) — a firewall discarding unsolicited traffic. The host does \
                     not fabricate open ports, so the list is still trustworthy; it just means an \
                     absent port cannot be distinguished from a blocked one.",
                    calib.controls_timed_out, calib.controls_probed
                )
            } else {
                "The port list is trustworthy as it stands.".to_string()
            };
            (
                Liveness::AliveConfirmed,
                format!("{} answered a real protocol. {how}", names.join(", ")),
            )
        }
    } else if blanket {
        (
            Liveness::AliveOpaque,
            format!(
                "{} of {} known-closed control ports completed a TCP handshake, so this host (or a \
                 SYN proxy / tarpit in front of it) answers indiscriminately. Not one port in the \
                 scanned range produced a nameable protocol, so no service could be proven. \
                 Something is on the path; what is behind it is unknown from this scan.",
                calib.controls_answered, calib.controls_probed
            ),
        )
    } else if real_count > 0 {
        (
            Liveness::AliveConfirmed,
            format!(
                "{real_count} port(s) completed a handshake on a host that refuses closed ports. \
                 No protocol was named, but the selectivity itself is the evidence."
            ),
        )
    } else if matches!(calib.posture, Posture::Silent) {
        (
            Liveness::NoResponse,
            format!(
                "Nothing answered and nothing was refused: all {} control probes and every scanned \
                 port timed out. Dropped, filtered, or dead — this scan genuinely cannot tell those \
                 apart. Try ICMP, a different vantage point, or a longer timeout.",
                calib.controls_timed_out
            ),
        )
    } else {
        // THE REFUSALS ARE THE EVIDENCE. This branch used to be unreachable for a
        // host with no open ports: `controls_answered == 0` implies `rtt_ms` is
        // None, so a host that RSTs every port fell into NoResponse and the report
        // said "cannot tell dead from dropped" about a host that had just answered
        // us twelve times.
        (
            Liveness::ReachableNoServices,
            format!(
                "{} of {} control ports were actively REFUSED, which is the host answering — it is \
                 up and reachable. Nothing in the scanned range is listening.",
                calib.controls_refused, calib.controls_probed
            ),
        )
    };

    HostVerdict {
        liveness,
        proof,
        real_count,
        fake_count,
        reasoning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coherent::Proto;
    
    #[test]
    fn the_two_no_open_port_cases_do_not_collapse_into_one_verdict() {
        let refusing = Calibration {
            posture: Posture::Discriminating, controls_probed: 12, controls_answered: 0,
            controls_refused: 12, controls_timed_out: 0, control_ports: vec![1],
            baseline: vec![], rtt_ms: None, l4_promoted: false,
        };
        let dropping = Calibration {
            posture: Posture::Silent, controls_probed: 12, controls_answered: 0,
            controls_refused: 0, controls_timed_out: 12, control_ports: vec![1],
            baseline: vec![], rtt_ms: None, l4_promoted: false,
        };
        assert_ne!(decide(&[], &refusing).liveness, decide(&[], &dropping).liveness,
                   "refused-everything and dropped-everything are different answers");
    }

    fn rep(port: u16, v: Verdict) -> PortReport {
        PortReport {
            port, verdict: v, why: String::new(), proto: None,
            sample: String::new(), connect_ms: 1,
        }
    }

    fn cal(posture: Posture, answered: usize) -> Calibration {
        Calibration {
            posture, controls_probed: 12, controls_answered: answered,
            controls_refused: 12 - answered, controls_timed_out: 0,
            control_ports: vec![50001], baseline: vec![], rtt_ms: Some(1), l4_promoted: false,
        }
    }

    #[test]
    fn one_real_service_proves_liveness_even_among_thousands_of_phantoms() {
        let mut reports = vec![rep(22, Verdict::Real(Proto::Ssh))];
        for p in 1000..2000u16 {
            reports.push(rep(p, Verdict::PhantomControlMatch));
        }
        let v = decide(&reports, &cal(Posture::Blanket, 12));
        assert_eq!(v.liveness, Liveness::AliveDeceptive);
        assert_eq!(v.proof, vec![(22, "ssh".to_string())]);
        assert_eq!(v.fake_count, 1000);
        assert_eq!(v.real_count, 1);
    }

    #[test]
    fn all_ports_open_but_nothing_behind_them_is_opaque_not_alive() {
        // The exact case this tool exists for.
        let reports: Vec<PortReport> =
            (1..500u16).map(|p| rep(p, Verdict::FakeIncoherent)).collect();
        let v = decide(&reports, &cal(Posture::Blanket, 12));
        assert_eq!(v.liveness, Liveness::AliveOpaque);
        assert!(v.proof.is_empty());
        assert!(v.reasoning.contains("no service could be proven"));
    }

    #[test]
    fn the_reasoning_never_claims_a_measurement_it_did_not_take() {
        // The hardened-firewall shape: a real service, closed ports DROPPED not refused.
        let dropping = Calibration {
            posture: Posture::Silent, controls_probed: 6, controls_answered: 0,
            controls_refused: 0, controls_timed_out: 6, control_ports: vec![1],
            baseline: vec![], rtt_ms: None, l4_promoted: false,
        };
        let v = decide(&[rep(443, Verdict::Real(Proto::Tls))], &dropping);
        assert_eq!(v.liveness, Liveness::AliveConfirmed);
        assert!(v.reasoning.contains("DROPPED"), "must say dropped: {}", v.reasoning);
        assert!(!v.reasoning.contains("are actively refused"),
                "must NOT claim refusals that did not happen: {}", v.reasoning);

        // And the refusing host must still say refused.
        let refusing = cal(Posture::Discriminating, 0);
        let v2 = decide(&[rep(443, Verdict::Real(Proto::Tls))], &refusing);
        assert!(v2.reasoning.contains("actively refused"), "{}", v2.reasoning);
        assert!(!v2.reasoning.contains("DROPPED"), "{}", v2.reasoning);
    }

    #[test]
    fn a_clean_host_with_services_is_simply_alive() {
        let reports = vec![
            rep(22, Verdict::Real(Proto::Ssh)),
            rep(443, Verdict::Real(Proto::Tls)),
        ];
        let v = decide(&reports, &cal(Posture::Discriminating, 0));
        assert_eq!(v.liveness, Liveness::AliveConfirmed);
        assert_eq!(v.proof.len(), 2);
    }

    #[test]
    fn a_host_that_refuses_every_port_is_alive_not_no_response() {
        // THE REGRESSION. A host RSTing every probe is answering us; reporting it as
        // "NO RESPONSE ... cannot tell dead from dropped" threw away the evidence.
        let v = decide(&[], &cal(Posture::Discriminating, 0));
        assert_eq!(v.liveness, Liveness::ReachableNoServices);
        assert!(v.reasoning.contains("REFUSED"), "must cite the refusals: {}", v.reasoning);
        assert!(!v.reasoning.contains("cannot tell"),
                "it CAN tell -- 12 refusals prove the host is up: {}", v.reasoning);
    }

    #[test]
    fn total_silence_is_reported_as_undecidable_not_as_dead() {
        // Only when NOTHING was refused either is the verdict genuinely undecidable.
        let c = Calibration {
            posture: Posture::Silent, controls_probed: 12, controls_answered: 0,
            controls_refused: 0, controls_timed_out: 12,
            control_ports: vec![50001], baseline: vec![], rtt_ms: None, l4_promoted: false,
        };
        let v = decide(&[], &c);
        assert_eq!(v.liveness, Liveness::NoResponse);
        assert!(v.reasoning.contains("cannot tell those apart"), "must not overclaim");
    }


}
