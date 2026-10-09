//! nmap-shaped output: `-oN` (normal), `-oG` (grepable) and `-oX` (XML).
//!
//! These exist so truemap can drop into a pipeline that already parses nmap. They
//! are nmap-SHAPED, not nmap: `scanner="truemap"` in the XML, and the service names
//! are truemap's protocol classes rather than entries from nmap's service database.
//! Claiming to be nmap in a file someone else's tooling reads would be a lie about
//! provenance, and the point of this tool is not to assert more than it measured.
//!
//! THE ONE DELIBERATE DIVERGENCE, because it will surprise anyone diffing the two:
//! a port that answered the handshake but could not be shown to run a service is
//! reported `closed`, not `open`. nmap reports every one of them `open` (often as
//! `tcpwrapped`). On a SYN-proxied host that is 65535 "open" ports with nothing
//! behind them, and encoding them as open would make `--open`, `grep open` and every
//! downstream consumer useless -- which is the problem truemap was written to solve.
//! Nothing is hidden: the `reason` attribute in XML and the `--reason` view carry
//! truemap's verdict verbatim, so the fact that the port ANSWERED is still on record.

use crate::adjudicate::Verdict;
use crate::output::HostOutput;

/// nmap's own extensions for `-oA`.
pub const EXT_NORMAL: &str = "nmap";
pub const EXT_GREP: &str = "gnmap";
pub const EXT_XML: &str = "xml";

/// What this run was invoked as, for the file headers.
pub fn argv_line() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

/// Seconds since the unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `Thu Oct  9 12:00:00 2026 UTC`, the shape nmap puts in its headers.
///
/// Computed here rather than pulled in as a dependency: a date crate for two header
/// lines is not worth the supply chain. The civil-from-days conversion is Howard
/// Hinnant's, and `date_parts` is unit-tested against known epochs.
pub fn utc_string(secs: u64) -> String {
    const DAY: u64 = 86_400;
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs / DAY;
    let rem = secs % DAY;
    let (y, m, d) = date_parts(days);
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {} UTC",
        WD[(days % 7) as usize],
        MON[(m - 1) as usize],
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        y
    )
}

/// Civil date from days since 1970-01-01 (Hinnant's algorithm).
fn date_parts(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// nmap's state word for a truemap verdict. See the divergence note at the top.
pub fn nmap_state(v: &Verdict) -> &'static str {
    if v.is_real() {
        "open"
    } else {
        "closed"
    }
}

/// A service token safe for nmap's delimited formats.
///
/// truemap's protocol names contain `/` (`smtp/ftp`), and `/` is the field separator
/// in grepable output -- emitting it raw would corrupt the record for every parser
/// downstream.
pub fn nmap_service(p: &crate::adjudicate::PortReport) -> String {
    let raw = match &p.verdict {
        Verdict::Real(proto) => proto.name(),
        Verdict::OpenUnidentified => "unknown",
        _ => "",
    };
    raw.replace(['/', '\t', '\n'], "-")
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            // Control characters are illegal in XML 1.0 even escaped, and banner
            // samples are arbitrary bytes from a hostile host.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {
                o.push_str(&format!("&#{};", c as u32))
            }
            c => o.push(c),
        }
    }
    o
}

/// The ports to list, and how many were left out.
///
/// nmap does not print its closed ports -- it prints `Not shown: 998 closed ports`
/// and `Ignored State: closed (998)` -- and on an answers-everything host that
/// convention is the difference between a 3-line file and a 65535-line one. `-v`
/// lists them, as it does in nmap.
fn listed<'a>(
    h: &'a HostOutput,
    list_closed: bool,
) -> (Vec<&'a crate::adjudicate::PortReport>, usize) {
    let shown: Vec<&crate::adjudicate::PortReport> = h
        .ports
        .iter()
        .filter(|p| list_closed || p.verdict.is_real())
        .collect();
    (shown, h.ports.len() - h.ports.iter().filter(|p| p.verdict.is_real()).count())
}

/// nmap's `-oN` layout.
pub fn normal(hosts: &[HostOutput], started: u64, finished: u64, list_closed: bool) -> String {
    let mut o = format!(
        "# truemap {} scan initiated {} as: {}\n",
        env!("CARGO_PKG_VERSION"),
        utc_string(started),
        argv_line()
    );
    let mut up = 0usize;
    for h in hosts {
        let alive = h.verdict.liveness.is_up();
        if alive {
            up += 1;
        }
        o.push('\n');
        if h.target == h.ip {
            o.push_str(&format!("truemap scan report for {}\n", h.ip));
        } else {
            o.push_str(&format!("truemap scan report for {} ({})\n", h.target, h.ip));
        }
        o.push_str(&format!(
            "Host is {} ({}).\n",
            if alive { "up" } else { "of undetermined state" },
            h.verdict.liveness.label()
        ));
        let (shown, closed) = listed(h, list_closed);
        // Only when they are actually hidden -- under -v they are all listed below,
        // and claiming something was "not shown" while showing it is just wrong.
        if closed > 0 && !list_closed {
            o.push_str(&format!(
                "Not shown: {closed} closed port(s) (answered at TCP but no service could \
                 be proved; -v lists them)\n"
            ));
        }
        if shown.is_empty() {
            o.push_str("All scanned ports are closed or unprovable.\n");
        } else {
            o.push_str("\nPORT      STATE  SERVICE          REASON\n");
            for p in &shown {
                o.push_str(&format!(
                    "{:<9} {:<6} {:<16} {}\n",
                    format!("{}/tcp", p.port),
                    nmap_state(&p.verdict),
                    {
                        let s = nmap_service(p);
                        if s.is_empty() { "-".to_string() } else { s }
                    },
                    p.verdict.label()
                ));
            }
        }
    }
    o.push_str(&format!(
        "\n# truemap done at {} -- {} address(es) ({} host(s) up) scanned in {:.2} seconds\n",
        utc_string(finished),
        hosts.len(),
        up,
        (finished.saturating_sub(started)) as f64
    ));
    o
}

/// nmap's `-oG` layout: one `Host:` record per host, `/`-delimited port fields.
pub fn grepable(hosts: &[HostOutput], started: u64, finished: u64, list_closed: bool) -> String {
    let mut o = format!(
        "# truemap {} scan initiated {} as: {}\n",
        env!("CARGO_PKG_VERSION"),
        utc_string(started),
        argv_line()
    );
    let mut up = 0usize;
    for h in hosts {
        let alive = h.verdict.liveness.is_up();
        if alive {
            up += 1;
        }
        let name = if h.target == h.ip { String::new() } else { h.target.clone() };
        o.push_str(&format!(
            "Host: {} ({})\tStatus: {}\n",
            h.ip,
            name,
            if alive { "Up" } else { "Unknown" }
        ));
        let (shown, closed) = listed(h, list_closed);
        if !shown.is_empty() || closed > 0 {
            // nmap's field order: port/state/proto/owner/service/rpc/version/
            let fields: Vec<String> = shown
                .iter()
                .map(|p| {
                    format!(
                        "{}/{}/tcp//{}///",
                        p.port,
                        nmap_state(&p.verdict),
                        nmap_service(p)
                    )
                })
                .collect();
            o.push_str(&format!(
                "Host: {} ({})\tPorts: {}",
                h.ip,
                name,
                fields.join(", ")
            ));
            if closed > 0 && !list_closed {
                o.push_str(&format!("\tIgnored State: closed ({closed})"));
            }
            o.push('\n');
        }
    }
    o.push_str(&format!(
        "# truemap done at {} -- {} address(es) ({} host(s) up) scanned in {:.2} seconds\n",
        utc_string(finished),
        hosts.len(),
        up,
        (finished.saturating_sub(started)) as f64
    ));
    o
}

/// nmap-shaped XML. `scanner="truemap"`, deliberately — see the module note.
pub fn xml(hosts: &[HostOutput], started: u64, finished: u64, list_closed: bool) -> String {
    let mut o = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    o.push_str(&format!(
        "<nmaprun scanner=\"truemap\" args=\"{}\" start=\"{}\" startstr=\"{}\" \
         version=\"{}\" xmloutputversion=\"1.05\">\n",
        esc(&argv_line()),
        started,
        esc(&utc_string(started)),
        env!("CARGO_PKG_VERSION")
    ));
    o.push_str("<scaninfo type=\"connect\" protocol=\"tcp\"/>\n");
    let mut up = 0usize;
    for h in hosts {
        let alive = h.verdict.liveness.is_up();
        if alive {
            up += 1;
        }
        o.push_str("<host>\n");
        o.push_str(&format!(
            "<status state=\"{}\" reason=\"{}\"/>\n",
            if alive { "up" } else { "unknown" },
            esc(h.verdict.liveness.label())
        ));
        let kind = if h.ip.contains(':') { "ipv6" } else { "ipv4" };
        o.push_str(&format!(
            "<address addr=\"{}\" addrtype=\"{}\"/>\n",
            esc(&h.ip), kind
        ));
        if h.target != h.ip {
            o.push_str(&format!(
                "<hostnames><hostname name=\"{}\" type=\"user\"/></hostnames>\n",
                esc(&h.target)
            ));
        }
        o.push_str("<ports>\n");
        let (shown, closed) = listed(h, list_closed);
        if closed > 0 && !list_closed {
            // nmap's own element for "scanned, uninteresting, not enumerated".
            o.push_str(&format!(
                "<extraports state=\"closed\" count=\"{closed}\">\
                 <extrareasons reason=\"no-service-proved\" count=\"{closed}\"/>\
                 </extraports>\n"
            ));
        }
        for p in shown {
            o.push_str(&format!(
                "<port protocol=\"tcp\" portid=\"{}\"><state state=\"{}\" reason=\"{}\"/>",
                p.port,
                nmap_state(&p.verdict),
                esc(&p.verdict.label())
            ));
            let svc = nmap_service(p);
            if !svc.is_empty() {
                o.push_str(&format!(
                    "<service name=\"{}\" method=\"probed\" conf=\"10\"/>",
                    esc(&svc)
                ));
            }
            // truemap's own evidence, in its own namespace-ish element so an nmap
            // parser ignores it rather than choking.
            o.push_str(&format!(
                "<truemap-evidence why=\"{}\" sample=\"{}\"/>",
                esc(&p.why),
                esc(&p.sample)
            ));
            o.push_str("</port>\n");
        }
        o.push_str("</ports>\n");
        o.push_str(&format!(
            "<truemap-calibration posture=\"{}\" controls_probed=\"{}\" \
             controls_answered=\"{}\" port_open_is_informative=\"{}\"/>\n",
            esc(h.calibration.posture.label()),
            h.calibration.controls_probed,
            h.calibration.controls_answered,
            h.calibration.l4_trustworthy()
        ));
        o.push_str("</host>\n");
    }
    o.push_str(&format!(
        "<runstats><finished time=\"{}\" timestr=\"{}\" elapsed=\"{:.2}\" exit=\"success\"/>\
         <hosts up=\"{}\" down=\"{}\" total=\"{}\"/></runstats>\n",
        finished,
        esc(&utc_string(finished)),
        (finished.saturating_sub(started)) as f64,
        up,
        hosts.len() - up,
        hosts.len()
    ));
    o.push_str("</nmaprun>\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjudicate::PortReport;
    use crate::calib::{Calibration, Posture};
    use crate::coherent::Proto;
    use crate::liveness::{HostVerdict, Liveness};

    fn rep(port: u16, v: Verdict) -> PortReport {
        PortReport {
            port,
            verdict: v,
            why: "because <it> said \"x\" & stopped".into(),
            proto: None,
            sample: "SSH-2.0\u{1}".into(),
            connect_ms: 1,
        }
    }

    fn host(ports: Vec<PortReport>) -> HostOutput {
        let real = ports.iter().filter(|p| p.verdict.is_real()).count();
        HostOutput {
            target: "h.example.com".into(),
            ip: "1.2.3.4".into(),
            calibration: Calibration {
                posture: Posture::Blanket,
                controls_probed: 12,
                controls_answered: 12,
                controls_refused: 0,
                controls_timed_out: 0,
                control_ports: vec![50001],
                baseline: vec![],
                rtt_ms: Some(2),
                l4_promoted: false,
            },
            l4: None,
            verdict: HostVerdict {
                liveness: Liveness::AliveDeceptive,
                proof: vec![],
                real_count: real,
                fake_count: ports.len() - real,
                reasoning: "r".into(),
            },
            ports,
            swept: 1000,
            answered_l4: 1000,
            sweep_bailed: true,
        }
    }

    #[test]
    fn the_date_header_matches_known_epochs() {
        assert_eq!(utc_string(0), "Thu Jan  1 00:00:00 1970 UTC");
        assert_eq!(utc_string(1_000_000_000), "Sun Sep  9 01:46:40 2001 UTC");
        // A leap day, which the civil-from-days conversion must get right.
        assert_eq!(utc_string(1_582_934_400), "Sat Feb 29 00:00:00 2020 UTC");
        assert_eq!(utc_string(1_583_020_800), "Sun Mar  1 00:00:00 2020 UTC");
    }

    #[test]
    fn a_fabricated_port_is_closed_not_open_in_every_format() {
        // The divergence from nmap that the module note explains. nmap calls these
        // open; reporting them open would make --open and `grep open` useless on
        // exactly the hosts truemap exists for.
        let h = vec![host(vec![
            rep(22, Verdict::Real(Proto::Ssh)),
            rep(81, Verdict::PhantomControlMatch),
        ])];
        for text in [
            normal(&h, 0, 1, false),
            grepable(&h, 0, 1, false),
            xml(&h, 0, 1, false),
        ] {
            assert!(text.contains("22"), "the real port must appear");
            let open_count = text.matches("open").count();
            assert!(open_count >= 1, "the real port must be open: {text}");
            assert!(
                !text.contains("81/open") && !text.contains("portid=\"81\"><state state=\"open\""),
                "a phantom port must not be reported open: {text}"
            );
        }
    }

    #[test]
    fn the_truemap_verdict_survives_as_the_reason_when_listed() {
        let h = vec![host(vec![rep(81, Verdict::Tarpit)])];
        assert!(normal(&h, 0, 1, true).contains("tarpit(accepted-then-froze)"));
        assert!(xml(&h, 0, 1, true).contains("reason=\"tarpit(accepted-then-froze)\""));
    }

    #[test]
    fn closed_ports_are_counted_not_enumerated_by_default() {
        // nmap's convention, and on an answers-everything host it is the difference
        // between a readable file and 65535 lines of nothing.
        let mut ports = vec![rep(22, Verdict::Real(Proto::Ssh))];
        for p in 1000..1100u16 {
            ports.push(rep(p, Verdict::FakeUniform));
        }
        let h = vec![host(ports)];

        let n = normal(&h, 0, 1, false);
        assert!(n.contains("Not shown: 100 closed port(s)"), "{n}");
        assert!(n.contains("22/tcp    open"), "{n}");
        assert!(!n.contains("1050/tcp"), "closed ports must not be enumerated: {n}");

        let g = grepable(&h, 0, 1, false);
        assert!(g.contains("22/open/tcp"), "{g}");
        assert!(!g.contains("1050/"), "{g}");
        assert!(g.contains("Ignored State: closed (100)"), "{g}");

        let x = xml(&h, 0, 1, false);
        assert!(x.contains("<extraports state=\"closed\" count=\"100\">"), "{x}");
        assert!(!x.contains("portid=\"1050\""), "{x}");
    }

    #[test]
    fn dash_v_enumerates_them_with_their_verdicts() {
        let mut ports = vec![rep(22, Verdict::Real(Proto::Ssh))];
        for p in 1000..1003u16 {
            ports.push(rep(p, Verdict::FakeUniform));
        }
        let h = vec![host(ports)];
        let n = normal(&h, 0, 1, true);
        assert!(n.contains("1002/tcp"), "-v must list them: {n}");
        assert!(n.contains("fake(uniform-banner)"), "with the reason: {n}");
        assert!(!n.contains("Not shown"), "nothing is hidden, so no summary line: {n}");
        let x = xml(&h, 0, 1, true);
        assert!(x.contains("portid=\"1002\""), "{x}");
        assert!(!x.contains("<extraports"), "{x}");
    }

    #[test]
    fn a_slash_in_a_service_name_cannot_corrupt_the_grepable_record() {
        // Proto::SmtpFtp is named "smtp/ftp", and '/' is the field separator.
        let h = vec![host(vec![rep(25, Verdict::Real(Proto::SmtpFtp))])];
        let g = grepable(&h, 0, 1, false);
        let ports_line = g.lines().find(|l| l.contains("Ports:")).unwrap();
        let record = ports_line.split("Ports: ").nth(1).unwrap();
        assert_eq!(
            record.split('/').count(),
            8,
            "a service name with a slash would add a field: {record}"
        );
        assert!(record.contains("smtp-ftp"), "{record}");
    }

    #[test]
    fn the_xml_escapes_markup_and_control_bytes_from_a_hostile_banner() {
        let h = vec![host(vec![rep(22, Verdict::Real(Proto::Ssh))])];
        let x = xml(&h, 0, 1, false);
        assert!(x.contains("&lt;it&gt;"), "angle brackets must be escaped: {x}");
        assert!(x.contains("&amp;"), "ampersands must be escaped");
        assert!(x.contains("&quot;"), "quotes inside attributes must be escaped");
        assert!(x.contains("&#1;"), "a raw control byte is illegal in XML 1.0: {x}");
        assert!(!x.contains("\u{1}"), "the raw byte must not survive");
    }

    #[test]
    fn the_xml_declares_truemap_as_the_scanner_not_nmap() {
        let h = vec![host(vec![rep(22, Verdict::Real(Proto::Ssh))])];
        assert!(xml(&h, 0, 1, false).contains("scanner=\"truemap\""));
    }
}
