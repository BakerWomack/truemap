//! Reporting. The guiding rule: never print 65535 lines of noise, and always say
//! which layer produced the verdict so a reader can argue with it.

use serde::Serialize;

use crate::adjudicate::{PortReport, Verdict};
use crate::calib::Calibration;
use crate::liveness::HostVerdict;
use crate::synack::L4Verdict;

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const OFF: &str = "\x1b[0m";

#[derive(Serialize)]
pub struct HostOutput {
    pub target: String,
    pub ip: String,
    pub calibration: Calibration,
    pub l4: Option<L4Verdict>,
    pub verdict: HostVerdict,
    pub ports: Vec<PortReport>,
    pub swept: usize,
    pub answered_l4: usize,
    pub sweep_bailed: bool,
}

/// The banner. rustscan prints ASCII art; this says what the tool is for, because
/// the one thing a user of this tool must understand is that "open" is not the
/// answer it reports.
pub fn banner(color: bool) -> String {
    let (b, d, off) = if color { (BOLD, DIM, OFF) } else { ("", "", "") };
    format!(
        "{b}\
   _                                       \n\
  | |_ _ __ _   _  ___ _ __ ___   __ _ _ __  \n\
  | __| '__| | | |/ _ \\ '_ ` _ \\ / _` | '_ \\ \n\
  | |_| |  | |_| |  __/ | | | | | (_| | |_) |\n\
   \\__|_|   \\__,_|\\___|_| |_| |_|\\__,_| .__/ \n\
                                      |_|    {off}\n\
  {d}a SYN-ACK is not a service. every port below was proved, or it is not listed.{off}\n"
    )
}

/// rustscan's greppable line: `ip -> [ports]`. Only PROVEN ports appear.
pub fn greppable_rustscan(h: &HostOutput) -> String {
    let ports: Vec<String> = h
        .ports
        .iter()
        .filter(|p| p.verdict.is_real())
        .map(|p| p.port.to_string())
        .collect();
    if ports.is_empty() {
        return String::new();
    }
    format!("{} -> [{}]\n", h.ip, ports.join(","))
}

/// How much of the report to render. Gathered into a struct because the flags that
/// steer it (`--open`, `--reason`, `-v`, `--show-fakes`) only ever travel together.
#[derive(Clone, Copy, Default)]
pub struct View {
    pub color: bool,
    pub show_fakes: bool,
    pub open_only: bool,
    pub reason: bool,
    pub verbose: u8,
}

impl View {
    /// `-v` implies listing the suppressed ports, as nmap's does.
    pub fn fakes_listed(&self) -> bool {
        self.show_fakes || self.verbose >= 1
    }
}

pub fn human(h: &HostOutput, view: &View) -> String {
    let color = view.color;
    let show_fakes = view.fakes_listed();
    let c = |s: &'static str| -> &'static str { if color { s } else { "" } };
    let mut o = String::new();

    o.push_str(&format!(
        "\n{}{} ({}){}\n",
        c(BOLD), h.target, h.ip, c(OFF)
    ));

    // Calibration first: it is the thing that makes the rest of the report mean
    // something, so it is not a footnote.
    let posture = h.calibration.posture.label();
    let pc = match h.calibration.posture {
        crate::calib::Posture::Discriminating => GREEN,
        crate::calib::Posture::Blanket => RED,
        _ => YELLOW,
    };
    o.push_str(&format!(
        "  {}calibration{}  {}{}{}  ({}/{} known-closed control ports answered",
        c(DIM), c(OFF), c(pc), posture, c(OFF),
        h.calibration.controls_answered, h.calibration.controls_probed
    ));
    if h.calibration.controls_answered == 0 {
        o.push_str(&format!(
            ", {} refused / {} dropped",
            h.calibration.controls_refused, h.calibration.controls_timed_out
        ));
    }
    if let Some(rtt) = h.calibration.rtt_ms {
        o.push_str(&format!(", rtt ~{rtt}ms"));
    }
    o.push_str(")\n");
    if !h.calibration.l4_trustworthy() {
        o.push_str(&format!(
            "  {}            \"port open\" carries no information on this host — every verdict \
             below comes from the application layer.{}\n",
            c(DIM), c(OFF)
        ));
    }

    if view.verbose >= 2 {
        o.push_str(&format!(
            "  {}             control ports: {}{}\n",
            c(DIM),
            brief_ports(&h.calibration.control_ports),
            c(OFF)
        ));
    }

    if let Some(l4) = &h.l4 {
        o.push_str(&format!(
            "  {}tcp-layer{}    {}\n",
            c(DIM), c(OFF), l4.note
        ));
    }

    o.push_str(&format!(
        "  {}sweep{}        {} ports probed, {} answered at TCP{}\n",
        c(DIM), c(OFF), h.swept, h.answered_l4,
        if h.sweep_bailed { " (stopped early: host answers indiscriminately)" } else { "" }
    ));

    let lc = match h.verdict.liveness {
        crate::liveness::Liveness::AliveConfirmed => GREEN,
        crate::liveness::Liveness::AliveDeceptive => YELLOW,
        crate::liveness::Liveness::AliveOpaque => RED,
        _ => DIM,
    };
    o.push_str(&format!(
        "  {}liveness{}     {}{}{}\n",
        c(DIM), c(OFF), c(lc), h.verdict.liveness.label(), c(OFF)
    ));
    o.push_str(&format!("  {}{}{}\n", c(DIM), wrap(&h.verdict.reasoning, 94, 16), c(OFF)));

    let real: Vec<&PortReport> = h.ports.iter().filter(|p| p.verdict.is_real()).collect();
    let fake: Vec<&PortReport> = h.ports.iter().filter(|p| p.verdict.is_fake()).collect();

    if !real.is_empty() {
        o.push_str(&format!(
            "\n  {}{:<8}{:<22}{}{}\n",
            c(BOLD), "PORT", "VERDICT", "EVIDENCE", c(OFF)
        ));
        for r in &real {
            let vc = if matches!(r.verdict, Verdict::Real(_)) { GREEN } else { CYAN };
            o.push_str(&format!(
                "  {:<8}{}{:<22}{}{}\n",
                r.port, c(vc), r.verdict.label(), c(OFF),
                truncate(&r.sample, 48)
            ));
            if view.reason {
                o.push_str(&format!(
                    "  {}        why: {}{}\n",
                    c(DIM), wrap(&r.why, 84, 13), c(OFF)
                ));
            }
        }
    } else {
        o.push_str(&format!(
            "\n  {}no port could be shown to run a real service{}\n", c(DIM), c(OFF)
        ));
    }

    if !fake.is_empty() && view.open_only {
        // --open: say how many were dropped, but not one line each. Staying silent
        // would hide that the host answered on 4312 ports, which is the finding.
        o.push_str(&format!(
            "\n  {}{} answering port(s) hidden by --open (none could be proved){}\n",
            c(DIM), fake.len(), c(OFF)
        ));
    } else if !fake.is_empty() {
        // Collapsed by default. This is the whole point: a reader should see "4312
        // fabricated" rather than 4312 lines.
        let mut by_reason: std::collections::BTreeMap<String, Vec<u16>> = Default::default();
        for f in &fake {
            by_reason.entry(f.verdict.label()).or_default().push(f.port);
        }
        o.push_str(&format!(
            "\n  {}{} fabricated / unprovable port(s) suppressed:{}\n",
            c(DIM), fake.len(), c(OFF)
        ));
        for (reason, ports) in &by_reason {
            o.push_str(&format!(
                "  {}  {:<34} {} ports{}{}\n",
                c(DIM), reason, ports.len(),
                if show_fakes { format!(": {}", brief_ports(ports)) } else { String::new() },
                c(OFF)
            ));
        }
        if view.reason || view.verbose >= 1 {
            // One `why` per distinct verdict, rather than the first port's only.
            let mut seen: std::collections::BTreeSet<String> = Default::default();
            for f in &fake {
                let label = f.verdict.label();
                if seen.insert(label.clone()) {
                    o.push_str(&format!(
                        "  {}  {}: {}{}\n",
                        c(DIM), label, wrap(&f.why, 84, 12), c(OFF)
                    ));
                }
            }
        } else if let Some(f) = fake.first() {
            o.push_str(&format!("  {}  why: {}{}\n", c(DIM), wrap(&f.why, 88, 12), c(OFF)));
        }
    }
    o
}

fn brief_ports(ports: &[u16]) -> String {
    let shown: Vec<String> = ports.iter().take(12).map(|p| p.to_string()).collect();
    if ports.len() > 12 {
        format!("{} … (+{})", shown.join(","), ports.len() - 12)
    } else {
        shown.join(",")
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

fn wrap(s: &str, width: usize, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut line = 0usize;
    for word in s.split_whitespace() {
        if line + word.len() + 1 > width {
            out.push('\n');
            out.push_str(&pad);
            line = 0;
        } else if line > 0 {
            out.push(' ');
            line += 1;
        }
        out.push_str(word);
        line += word.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calib::Posture;
    use crate::coherent::Proto;
    use crate::liveness::Liveness;

    fn out(ports: Vec<PortReport>, posture: Posture) -> HostOutput {
        HostOutput {
            target: "t".into(), ip: "1.2.3.4".into(),
            calibration: Calibration {
                posture, controls_probed: 12,
                controls_answered: if matches!(posture, Posture::Blanket) { 12 } else { 0 },
                controls_refused: if matches!(posture, Posture::Blanket) { 0 } else { 12 },
                controls_timed_out: 0,
                control_ports: vec![50001], baseline: vec![], rtt_ms: Some(2), l4_promoted: false,
            },
            l4: None,
            verdict: HostVerdict {
                liveness: Liveness::AliveDeceptive, proof: vec![(22, "ssh".into())],
                real_count: 1, fake_count: ports.len() - 1,
                reasoning: "r".into(),
            },
            ports, swept: 65535, answered_l4: 65535, sweep_bailed: true,
        }
    }

    fn rep(port: u16, v: Verdict) -> PortReport {
        PortReport { port, verdict: v, why: "because".into(), proto: None,
                     sample: String::new(), connect_ms: 1 }
    }

    #[test]
    fn thousands_of_phantoms_collapse_to_a_summary_not_thousands_of_lines() {
        let mut ports = vec![rep(22, Verdict::Real(Proto::Ssh))];
        for p in 1000..5000u16 {
            ports.push(rep(p, Verdict::PhantomControlMatch));
        }
        let text = human(&out(ports, Posture::Blanket), &View::default());
        let lines = text.lines().count();
        assert!(lines < 30, "report must stay readable, got {lines} lines");
        assert!(text.contains("4000 fabricated"), "must state the count: {text}");
        assert!(text.contains("real:ssh"), "must still show the real service");
        // The individual phantom ports must NOT be listed by default.
        assert!(!text.contains("4999"), "phantom ports must be suppressed");
    }

    #[test]
    fn the_rustscan_greppable_line_lists_only_proven_ports() {
        let ports = vec![
            rep(22, Verdict::Real(Proto::Ssh)),
            rep(443, Verdict::Real(Proto::Tls)),
            rep(1000, Verdict::PhantomControlMatch),
        ];
        let g = greppable_rustscan(&out(ports, Posture::Blanket));
        assert_eq!(g, "1.2.3.4 -> [22,443]\n", "rustscan's format, proven ports only");
        assert!(!g.contains("1000"), "fabricated ports must not be piped onward");
    }

    #[test]
    fn a_host_with_nothing_proven_emits_no_greppable_line_at_all() {
        let ports = vec![rep(1000, Verdict::PhantomControlMatch)];
        let mut o = out(ports, Posture::Blanket);
        o.verdict.real_count = 0;
        assert_eq!(greppable_rustscan(&o), "",
                   "a blanket host with no services must not emit a port list");
    }

    #[test]
    fn open_only_reports_the_count_but_not_the_breakdown() {
        // --open must still say the host answered on those ports. Dropping the fact
        // entirely would hide the finding that matters on a SYN-proxied host.
        let mut ports = vec![rep(22, Verdict::Real(Proto::Ssh))];
        for p in 1000..1050u16 {
            ports.push(rep(p, Verdict::PhantomControlMatch));
        }
        let v = View { open_only: true, ..Default::default() };
        let text = human(&out(ports, Posture::Blanket), &v);
        assert!(text.contains("real:ssh"));
        assert!(text.contains("50 answering port(s) hidden"), "{text}");
        assert!(!text.contains("phantom(matches-closed-control)"), "{text}");
    }

    #[test]
    fn reason_gives_one_why_per_verdict_not_just_the_first_ports() {
        let ports = vec![
            rep(1000, Verdict::PhantomControlMatch),
            rep(1001, Verdict::Tarpit),
        ];
        let v = View { reason: true, ..Default::default() };
        let text = human(&out(ports, Posture::Blanket), &v);
        assert!(text.contains("phantom(matches-closed-control):"), "{text}");
        assert!(text.contains("tarpit(accepted-then-froze):"), "{text}");
    }

    #[test]
    fn dash_v_lists_the_suppressed_ports_without_show_fakes() {
        let ports = vec![
            rep(22, Verdict::Real(Proto::Ssh)),
            rep(1234, Verdict::FakeUniform),
        ];
        let v = View { verbose: 1, ..Default::default() };
        let text = human(&out(ports, Posture::Blanket), &v);
        assert!(text.contains("1234"), "-v must name them: {text}");
    }

    #[test]
    fn dash_v_v_shows_the_control_ports_that_calibration_used() {
        let v = View { verbose: 2, ..Default::default() };
        let text = human(&out(vec![rep(22, Verdict::Real(Proto::Ssh))], Posture::Blanket), &v);
        assert!(text.contains("control ports: 50001"), "{text}");
    }

    #[test]
    fn a_clean_host_report_does_not_mention_suppression() {
        let text = human(&out(vec![rep(22, Verdict::Real(Proto::Ssh))], Posture::Discriminating),
                         &View::default());
        assert!(!text.contains("fabricated"));
        assert!(text.contains("discriminating"));
    }
}
