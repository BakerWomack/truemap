//! Calibration: learn what a *closed* port looks like on this specific host.
//!
//! This is the answer to "every port says open but nothing is there."
//!
//! A port scanner normally has no negative control. It sends a SYN, gets a
//! SYN-ACK, and reports "open" — which is correct only if the host answers SYN
//! *selectively*. Behind a SYN proxy, a SYN-cookie firewall (F5, Fortinet,
//! SonicWall, AWS Global Accelerator) or a tarpit, the host answers every SYN,
//! and "open" stops carrying information.
//!
//! So before scanning, we probe a handful of ports chosen at random from high
//! ephemeral space — ports that are almost certainly *not* listening. Whatever
//! those do is what "closed" looks like here. Then:
//!
//!   * controls all refused  -> the host discriminates. Normal scan semantics.
//!   * controls all answered -> the host answers everything. L4 state is noise,
//!                              and the control signature is the phantom template
//!                              every fabricated port will match.
//!   * controls split        -> partial/flaky responder. Scan, but trust nothing
//!                              that is not confirmed at the application layer.

use std::net::IpAddr;

use rand::Rng;
use serde::Serialize;

use crate::probe::{probe, Dial, Payload, ProbeCfg, Signature};

/// How many control ports to burn on calibration. Twelve is plenty: the chance
/// that a host genuinely listens on all twelve random high ports is negligible,
/// and the chance it listens on *none* of them is overwhelming.
pub const DEFAULT_CONTROLS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Posture {
    /// Closed ports refuse. "Open" means open.
    Discriminating,
    /// Some control ports answered. Partial responder, or packet loss. Suspicious.
    Flaky,
    /// Every control port answered. "Open" means nothing at layer 4.
    Blanket,
    /// No control port answered AND none was refused — every probe timed out.
    /// Dropped, filtered or dead, and this scan cannot tell those apart.
    Silent,
}

impl Posture {
    pub fn label(self) -> &'static str {
        match self {
            Posture::Discriminating => "discriminating",
            Posture::Flaky => "flaky-responder",
            Posture::Blanket => "answers-everything",
            Posture::Silent => "silent/filtered",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Calibration {
    pub posture: Posture,
    pub controls_probed: usize,
    pub controls_answered: usize,
    /// Controls that were actively REFUSED. A non-zero count is positive proof the
    /// host is reachable, which is why it is recorded separately from "not open".
    pub controls_refused: usize,
    /// Controls that produced nothing at all.
    pub controls_timed_out: usize,
    /// Control ports used, so a reader can reproduce the calibration exactly.
    pub control_ports: Vec<u16>,
    /// The behavioural signatures of the known-closed ports. A candidate port
    /// that matches one of these is fabricated — not by inference, but because it
    /// is indistinguishable from a port we know nothing is listening on.
    pub baseline: Vec<Signature>,
    /// Median connect RTT across answering controls, used to tune timeouts.
    pub rtt_ms: Option<u64>,
    /// True when the posture was firmed up by the raw SYN-ACK evidence rather than
    /// by the connect count alone.
    pub l4_promoted: bool,
}

impl Calibration {
    /// Does this candidate port behave exactly like a known-closed port?
    pub fn is_phantom(&self, sig: &Signature) -> bool {
        self.baseline.iter().any(|b| sig.matches(b))
    }

    /// Can layer-4 "open" be trusted on this host at all?
    ///
    /// `Silent` counts as trustworthy, and getting that wrong produced two false
    /// statements in one report. Measured against a hardened internet-facing host whose
    /// firewall DROPS unsolicited ports instead of refusing them, so the posture is
    /// `Silent` — and because only `Discriminating` was trusted here, the run announced
    /// "this host answers every port" about a host where exactly two of forty-two
    /// answered.
    ///
    /// The distinction that matters is NOT refuse-versus-drop. It is whether the host
    /// FABRICATES open ports. A silent host does not: its closed ports time out and
    /// its open ports complete a handshake, so "open" means open. Only a blanket or
    /// flaky responder makes layer-4 state meaningless.
    pub fn l4_trustworthy(&self) -> bool {
        matches!(self.posture, Posture::Discriminating | Posture::Silent)
    }

    /// Firm up the posture using the raw SYN-ACK evidence, when we have it.
    ///
    /// Calibration is a *connect* scan, and a connect scan can undercount. Against
    /// netfilter DELUDE — which SYN-ACKs every port and then RSTs the final ACK —
    /// the reset races `connect()`, so only a fraction of the control ports appear
    /// to answer and the posture flaps between `Blanket` and `Flaky` run to run.
    /// Measured: 53, 62 and 63 of 200 ports on three consecutive runs,
    /// where nmap's SYN scan saw all 200.
    ///
    /// The SYN-ACK does not suffer that race. So when the layer-4 test is usable
    /// and says every reply it read carried a tarpit shape, that is stronger
    /// evidence than the connect count, and the posture is promoted. Only ever a
    /// promotion toward "answers everything" — this must not be able to launder a
    /// discriminating host into a trusted one.
    pub fn reinforce_with_l4(&mut self, tarpit_ports: usize, real_ports: usize, usable: bool) {
        if usable && tarpit_ports > 0 && real_ports == 0 {
            self.posture = Posture::Blanket;
            self.l4_promoted = true;
        }
    }
}

/// Pick control ports: random, high, and re-rolled each run so a target cannot
/// pre-arrange to answer only the ports we check.
///
/// `exclude` is a *preference*, not a constraint. It exists only to avoid probing a
/// port the sweep will cover anyway, which is cosmetic. It must never be allowed to
/// make the function fail to return: with `-p all` every candidate is in the scan
/// list, and treating the exclusion as hard turns this into an infinite loop.
pub fn pick_control_ports(n: usize, exclude: &[u16]) -> Vec<u16> {
    let mut rng = rand::thread_rng();
    let mut out: Vec<u16> = Vec::with_capacity(n);
    // 45000-65500: above the common service range, inside unprivileged space.
    const LO: u16 = 45000;
    const HI: u16 = 65500;
    // Bounded: enough draws to fill `n` comfortably when the range is mostly free,
    // then give up on the preference rather than on the function.
    let budget = (n * 64).max(512);
    for _ in 0..budget {
        if out.len() == n {
            return out;
        }
        let p: u16 = rng.gen_range(LO..=HI);
        if !out.contains(&p) && !exclude.contains(&p) {
            out.push(p);
        }
    }
    // Fall back to distinct random ports, ignoring the exclusion. A control port
    // that is also in the scan range is still a control port — we probe it, learn
    // what it does, and that is the whole job.
    while out.len() < n {
        let p: u16 = rng.gen_range(LO..=HI);
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Probe the control ports and derive the host's posture.
pub async fn calibrate(
    ip: IpAddr,
    n: usize,
    exclude: &[u16],
    cfg: &ProbeCfg,
) -> Calibration {
    let control_ports = pick_control_ports(n, exclude);

    // Probe each control port with the same ladder a real candidate gets, so the
    // signatures are directly comparable. Alternate the payload so the baseline
    // covers both nudges.
    let futs = control_ports.iter().enumerate().map(|(i, &p)| {
        let payload = if i % 2 == 0 { Payload::Http } else { Payload::Tls };
        async move { probe(ip, p, payload, cfg).await }
    });
    let sigs: Vec<Signature> = futures::future::join_all(futs).await;

    let answered: Vec<&Signature> = sigs.iter().filter(|s| s.connected).collect();
    let n_ans = answered.len();

    let n_refused = sigs.iter().filter(|s| s.dial == Dial::Refused).count();
    let n_timeout = sigs.iter().filter(|s| s.dial == Dial::TimedOut).count();

    let posture = if n_ans == 0 {
        // DISTINGUISHING "REFUSED" FROM "TIMED OUT" IS THE WHOLE LIVENESS ANSWER.
        //
        // Both mean "not open", and collapsing them was a real bug: a host that
        // RSTs every port is demonstrably alive -- the RST is the host answering --
        // and truemap reported it as NO RESPONSE, "cannot tell dead from dropped".
        // It could tell. It threw the evidence away at the connect call.
        if n_refused > 0 {
            Posture::Discriminating
        } else {
            Posture::Silent
        }
    } else if n_ans == control_ports.len() {
        Posture::Blanket
    } else if n_ans * 2 >= control_ports.len() {
        Posture::Blanket // a clear majority answering is still an answer-everything host
    } else {
        Posture::Flaky
    };

    let rtt_ms = if n_ans > 0 {
        let mut v: Vec<u64> = answered.iter().map(|s| s.connect_ms).collect();
        v.sort_unstable();
        Some(v[v.len() / 2])
    } else {
        None
    };

    // Only answering controls contribute a baseline shape — an unreachable control
    // tells us nothing to compare against.
    let baseline: Vec<Signature> = sigs.iter().filter(|s| s.connected).cloned().collect();

    Calibration {
        posture,
        controls_probed: control_ports.len(),
        controls_answered: n_ans,
        controls_refused: n_refused,
        controls_timed_out: n_timeout,
        control_ports,
        baseline,
        rtt_ms,
        l4_promoted: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Close, Spoke};

    fn sig(connected: bool, hash: u64, spoke: Spoke, close: Close) -> Signature {
        Signature {
            connected,
            dial: if connected { Dial::Connected } else { Dial::Refused },
            connect_ms: 1, bytes: 0, hash, proto: None,
            spoke, close, sample: String::new(),
        }
    }

    #[test]
    fn control_ports_are_high_distinct_and_rerolled() {
        let a = pick_control_ports(12, &[]);
        assert_eq!(a.len(), 12);
        assert!(a.iter().all(|&p| p >= 45000), "controls must be high ports");
        let mut s = a.clone();
        s.sort_unstable();
        s.dedup();
        assert_eq!(s.len(), 12, "controls must be distinct");
        // Re-rolled per run: two draws of 12 from a 20k space should differ.
        let b = pick_control_ports(12, &[]);
        assert_ne!(a, b, "control ports must be re-rolled each run");
    }

    #[test]
    fn scanning_every_port_still_yields_controls_and_does_not_hang() {
        // Regression: `-p all` passes every port as the exclusion set. Treating that
        // as a hard constraint made this loop forever, so `truemap host -p all` hung
        // before sending a single packet.
        let all: Vec<u16> = (1..=65535u16).collect();
        let picked = pick_control_ports(12, &all);
        assert_eq!(picked.len(), 12);
        let mut d = picked.clone();
        d.sort_unstable();
        d.dedup();
        assert_eq!(d.len(), 12, "controls must still be distinct");
        assert!(picked.iter().all(|&p| (45000..=65500).contains(&p)));
    }

    #[test]
    fn exclusions_are_respected() {
        let banned: Vec<u16> = (45000..=65500).filter(|p| p % 2 == 0).collect();
        let picked = pick_control_ports(8, &banned);
        assert!(picked.iter().all(|p| p % 2 == 1));
    }

    #[test]
    fn a_port_matching_a_known_closed_port_is_phantom() {
        let c = Calibration {
            posture: Posture::Blanket,
            controls_probed: 2,
            controls_answered: 2,
            controls_refused: 0,
            controls_timed_out: 0,
            control_ports: vec![50001, 50002],
            baseline: vec![sig(true, 0, Spoke::Nothing, Close::HeldOpen)],
            rtt_ms: Some(1),
            l4_promoted: false,
        };
        // Behaves exactly like a port we know is closed -> fabricated.
        assert!(c.is_phantom(&sig(true, 0, Spoke::Nothing, Close::HeldOpen)));
        // Spoke a real protocol -> not phantom.
        let mut real = sig(true, 777, Spoke::Greeting, Close::EofAfterData);
        real.proto = Some(crate::coherent::Proto::Ssh);
        assert!(!c.is_phantom(&real));
        assert!(!c.l4_trustworthy());
    }

    #[test]
    fn a_silent_host_still_discriminates_so_open_means_open() {
        // The hardened-firewall shape: closed ports dropped, not refused. It does not fabricate
        // open ports, so the port list is trustworthy and the "answers every port"
        // path must not be taken.
        let c = Calibration {
            posture: Posture::Silent, controls_probed: 6, controls_answered: 0,
            controls_refused: 0, controls_timed_out: 6, control_ports: vec![50001],
            baseline: vec![], rtt_ms: None, l4_promoted: false,
        };
        assert!(c.l4_trustworthy(), "dropping closed ports is not fabricating open ones");
        // And with no answering controls there is no baseline, so nothing is phantom.
        assert!(!c.is_phantom(&sig(true, 7, Spoke::Greeting, Close::EofAfterData)));
    }

    #[test]
    fn l4_evidence_promotes_a_flaky_posture_but_never_launders_a_clean_host() {
        // DELUDE case: the connect scan undercounted, but every SYN-ACK read was
        // tarpit-shaped.
        let mut c = Calibration {
            posture: Posture::Flaky, controls_probed: 12, controls_answered: 4,
            controls_refused: 8, controls_timed_out: 0,
            control_ports: vec![50001], baseline: vec![], rtt_ms: Some(1),
            l4_promoted: false,
        };
        c.reinforce_with_l4(200, 0, true);
        assert_eq!(c.posture, Posture::Blanket);
        assert!(c.l4_promoted);

        // A blind layer-4 test must change nothing.
        let mut c2 = Calibration {
            posture: Posture::Discriminating, controls_probed: 12, controls_answered: 0,
            controls_refused: 12, controls_timed_out: 0,
            control_ports: vec![50001], baseline: vec![], rtt_ms: None, l4_promoted: false,
        };
        c2.reinforce_with_l4(0, 0, false);
        assert_eq!(c2.posture, Posture::Discriminating, "must not promote on no evidence");
        assert!(c2.l4_trustworthy());

        // Real ports present at layer 4 means the signal is not a blanket tarpit.
        let mut c3 = c2.clone();
        c3.reinforce_with_l4(3, 5, true);
        assert_eq!(c3.posture, Posture::Discriminating);
    }
}
