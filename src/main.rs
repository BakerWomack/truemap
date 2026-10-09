//! truemap — a rustscan-compatible TCP scanner that proves which ports are real.
//!
//! The problem it solves: a SYN proxy, a SYN-cookie firewall or a tarpit answers
//! every SYN, so an ordinary scanner reports thousands of open ports with nothing
//! behind them. truemap calibrates against known-closed control ports on the same
//! host first, so it knows what "closed" looks like there, then proves each
//! candidate at the application layer — and hands nmap only what it proved.

mod adjudicate;
mod calib;
mod cli;
mod coherent;
mod liveness;
mod nmap;
mod nmapout;
mod output;
mod ports;
mod probe;
mod sweep;
mod synack;
mod target;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use clap::Parser;

use crate::cli::{Args, Scripts};
use crate::probe::ProbeCfg;

#[tokio::main]
async fn main() {
    // nmap's `-iL` and `-p-` are rewritten into flags clap can express before it
    // ever sees them; see cli::rewrite_nmap_flags for why they cannot be declared.
    let rewritten = cli::rewrite_nmap_flags(std::env::args());
    if !rewritten.errors.is_empty() {
        for e in &rewritten.errors {
            eprintln!("truemap: {e}");
        }
        std::process::exit(2);
    }
    let args = Args::parse_from(rewritten.argv);

    if args.udp {
        eprintln!(
            "truemap: --udp is not supported. truemap is TCP-only: its whole method is \
             completing a handshake and then proving the service at the application \
             layer, and UDP has no handshake to calibrate against. Use `nmap -sU` for UDP. \
             Failing here rather than silently scanning TCP and labelling it UDP."
        );
        std::process::exit(2);
    }

    // Flags truemap accepts only so they fail loudly. Refusing here, before any
    // packet, is the point: an ignored -e/-g would mean the scan went out from
    // somewhere other than where the operator believes it did.
    let refusals = args.refusals();
    if !refusals.is_empty() {
        for r in &refusals {
            eprintln!("truemap: {r}");
        }
        std::process::exit(2);
    }

    let port_list = match args.port_list() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("truemap: {e}");
            std::process::exit(2);
        }
    };

    let specs = match args.target_specs() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("truemap: {e}");
            std::process::exit(2);
        }
    };
    if specs.is_empty() {
        eprintln!(
            "truemap: no targets. Pass them positionally, with -a/--addresses, or with \
             -iL <file>."
        );
        std::process::exit(2);
    }

    // Exclusions are resolved to NETWORKS and applied per address below, not by
    // string-matching the specs. `-iL scope.txt -x 10.0.0.5` has to work when
    // 10.0.0.5 is reached via a CIDR in the file, which is the whole point of -x.
    // A malformed -x is fatal: continuing would scan the address it names.
    let mut exclude_specs = args.exclude_addresses.clone();
    if let Some(f) = &args.exclude_file {
        match target::read_target_list(f) {
            Ok(v) => exclude_specs.extend(v),
            Err(e) => {
                eprintln!("truemap: --excludefile {e}");
                std::process::exit(2);
            }
        }
    }
    let (excluded, bad_excludes) = target::exclusion_nets(&exclude_specs);
    if !bad_excludes.is_empty() {
        for b in &bad_excludes {
            eprintln!("truemap: -x {b}");
        }
        eprintln!(
            "truemap: refusing to scan with an exclusion that could not be resolved -- \
             it would not have excluded anything."
        );
        std::process::exit(2);
    }

    // -n means never resolve. A hostname target cannot be honoured without DNS, so
    // it is an error rather than a silent skip.
    if args.no_dns {
        let names: Vec<&String> = specs
            .iter()
            .filter(|s| s.parse::<std::net::IpAddr>().is_err() && s.parse::<ipnet::IpNet>().is_err())
            .collect();
        if !names.is_empty() {
            eprintln!(
                "truemap: -n/--no-dns forbids resolution, but {} target(s) are hostnames: {}",
                names.len(),
                names
                    .iter()
                    .take(5)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(2);
        }
    }

    let mut hosts: Vec<(String, IpAddr)> = Vec::new();
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for t in &specs {
        match target::resolve_targets(t) {
            Ok(v) => {
                for (name, ip) in v {
                    if target::is_excluded(&ip, &excluded) {
                        skipped += 1;
                        continue;
                    }
                    // Overlapping entries in a list file are normal -- a CIDR and one
                    // of its hosts, or the same host twice. Scanning an address twice
                    // wastes the budget and doubles the rate seen by that address.
                    if !hosts.iter().any(|(n, i)| *i == ip && *n == name) {
                        hosts.push((name, ip));
                    }
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("truemap: {e}");
            }
        }
    }
    if hosts.is_empty() {
        if skipped > 0 && failed == 0 {
            eprintln!("truemap: every target was excluded by -x; nothing to scan");
        } else {
            eprintln!("truemap: no resolvable targets");
        }
        std::process::exit(2);
    }

    let color = args.use_color();
    if !args.terse() && !args.accessible {
        print!("{}", output::banner(color));
    }

    let (limit, warn) = cli::set_ulimit(args.ulimit);
    if let Some(w) = warn {
        eprintln!("truemap: {w}");
    }
    let concurrency = sweep::default_concurrency(Some(args.batch_size));
    if !args.terse() {
        if skipped > 0 {
            eprintln!("truemap: {skipped} address(es) excluded by -x");
        }
        eprintln!(
            "truemap: {} host(s), {} port(s), batch {} (fd limit {}), {} control port(s) per host",
            hosts.len(),
            port_list.len(),
            concurrency,
            limit,
            args.controls
        );
        if args.l4 && !synack::available() {
            eprintln!("truemap: {}", synack::unavailable_reason());
        }
    }

    // The priority set: where real services actually live. Probed first so the early
    // bail on an answers-everything host cannot skip them.
    let mut priority: Vec<u16> = ports::ANCHORS.to_vec();
    for &p in ports::TOP_1000 {
        if !priority.contains(&p) {
            priority.push(p);
        }
    }

    let view = output::View {
        color,
        show_fakes: args.show_fakes,
        open_only: args.open,
        reason: args.reason,
        verbose: args.verbose,
    };
    if args.debug >= 1 {
        eprintln!(
            "truemap: [debug] {} spec(s) -> {} host(s); order {:?}; timeout {}ms; tries {}",
            specs.len(),
            hosts.len(),
            args.order(),
            args.timeout,
            args.tries
        );
    }

    let run_started = nmapout::now_secs();
    let mut all: Vec<output::HostOutput> = Vec::new();

    for (name, ip) in hosts {
        let started = Instant::now();
        let cfg = ProbeCfg {
            connect_timeout: Duration::from_millis(args.timeout),
            greet_timeout: Duration::from_millis(args.timeout.max(1200)),
            read_timeout: Duration::from_millis(args.timeout.max(1500)),
            sni: name.clone(),
        };

        // ---- Phase 0: calibrate. Learn what closed looks like HERE. ----
        let mut calibration = calib::calibrate(ip, args.controls, &port_list, &cfg).await;

        // ---- Phase 0b (optional, privileged): read the SYN-ACKs themselves. ----
        let l4 = if args.l4 && synack::available() {
            if let IpAddr::V4(v4) = ip {
                l4_probe(v4, &port_list).await
            } else {
                None
            }
        } else {
            None
        };
        // The connect scan can undercount a host that resets established connections
        // (DELUDE). When the raw SYN-ACKs say otherwise, believe them.
        if let Some(v) = &l4 {
            calibration.reinforce_with_l4(v.tarpit.len(), v.real.len(), v.usable);
        }

        // ---- Phase 1: the fast sweep. ----
        let scfg = sweep::SweepCfg {
            concurrency,
            timeout: Duration::from_millis(args.timeout),
            tries: args.tries,
            order: args.order(),
            announce: !args.terse(),
            bail_after: args.bail_after,
        };
        let swept = sweep::sweep(ip, &port_list, &priority, calibration.posture, &scfg).await;

        // ---- Phase 2: decide what to prove. ----
        let candidates: Vec<u16> = if calibration.l4_trustworthy() {
            swept.answered.clone()
        } else {
            // On an answers-everything host the sweep may have bailed, so its answered
            // set is a sample, not the truth. Start from the anchors unconditionally —
            // a host that answers everything answers those too, and that is what stops
            // the bail from hiding ssh or https.
            let mut c: Vec<u16> = ports::ANCHORS
                .iter()
                .copied()
                .filter(|p| port_list.contains(p))
                .collect();
            let extra: &[u16] = if args.deep { &swept.answered } else { &priority };
            for &p in extra {
                if !c.contains(&p) && swept.answered.contains(&p) {
                    c.push(p);
                }
            }
            c.sort_unstable();
            c
        };

        if !args.terse() && !calibration.l4_trustworthy() && !args.deep {
            eprintln!(
                "truemap: {name} answers every port — proving the {} likely-service port(s) \
                 rather than all {}. Use --deep to prove every answering port.",
                candidates.len(),
                swept.answered.len()
            );
        }

        let reports =
            adjudicate::adjudicate(ip, &candidates, &calibration, &cfg, args.adjudicate_batch)
                .await;
        let verdict = liveness::decide(&reports, &calibration);

        let ho = output::HostOutput {
            target: name.clone(),
            ip: ip.to_string(),
            calibration,
            l4,
            verdict,
            ports: reports,
            swept: swept.probed,
            answered_l4: swept.answered.len(),
            sweep_bailed: swept.bailed,
        };

        if args.greppable || args.quiet {
            print!("{}", output::greppable_rustscan(&ho));
        } else if !args.json && !args.stdout_is_a_report() {
            print!("{}", output::human(&ho, &view));
            eprintln!("  (host finished in {:.1}s)", started.elapsed().as_secs_f64());
        }
        if args.debug >= 1 {
            eprintln!(
                "truemap: [debug] {} adjudicated {} candidate(s) in {:.2}s",
                ho.ip,
                ho.ports.len(),
                started.elapsed().as_secs_f64()
            );
        }

        // ---- The nmap hand-off: the PROVEN ports only. ----
        if args.run_nmap() {
            let proven: Vec<u16> = ho
                .ports
                .iter()
                .filter(|p| p.verdict.is_real())
                .map(|p| p.port)
                .collect();
            if proven.is_empty() {
                eprintln!(
                    "truemap: not running nmap on {name} — no port could be proved to run a \
                     service. rustscan would hand nmap all {} answering ports here; every one \
                     of them would come back `tcpwrapped`.",
                    ho.answered_l4
                );
            } else if let Err(e) = nmap::run(&args.command, &proven, &name) {
                eprintln!("truemap: {e}");
            }
        } else if args.scripts == Scripts::None && !args.command.is_empty() && !args.terse() {
            eprintln!("truemap: --scripts none, so nmap was not run.");
        }

        all.push(ho);
    }

    if let Err(e) = write_reports(&args, &all, run_started) {
        eprintln!("truemap: {e}");
        std::process::exit(1);
    }

    if args.json {
        match serde_json::to_string_pretty(&all) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("truemap: json encode failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // Exit 1 when no host could be shown to run a service: useful in pipelines.
    if !all.iter().any(|h| h.verdict.real_count > 0) {
        std::process::exit(1);
    }
}

/// Write whichever of `-oN`/`-oG`/`-oX`/`-oA` were asked for.
///
/// `-` means stdout, as in nmap. Failing to write a requested report is fatal: the
/// operator asked for a record of the scan, and silently not producing one leaves
/// them believing it exists.
fn write_reports(
    args: &Args,
    all: &[output::HostOutput],
    started: u64,
) -> Result<(), String> {
    let finished = nmapout::now_secs();
    // nmap does not enumerate closed ports unless asked; -v asks. `--open` and the
    // default coincide here, which is faithful to nmap.
    let list_closed = args.verbose >= 1;

    let mut jobs: Vec<(String, String)> = Vec::new();
    if let Some(f) = &args.output_normal {
        jobs.push((f.clone(), nmapout::normal(all, started, finished, list_closed)));
    }
    if let Some(f) = &args.output_grep {
        jobs.push((f.clone(), nmapout::grepable(all, started, finished, list_closed)));
    }
    if let Some(f) = &args.output_xml {
        jobs.push((f.clone(), nmapout::xml(all, started, finished, list_closed)));
    }
    if let Some(base) = &args.output_all {
        if base == "-" {
            return Err(
                "-oA writes three files and so needs a basename, not `-`. Use -oN/-oG/-oX                  individually to send one of them to stdout."
                    .into(),
            );
        }
        jobs.push((
            format!("{base}.{}", nmapout::EXT_NORMAL),
            nmapout::normal(all, started, finished, list_closed),
        ));
        jobs.push((
            format!("{base}.{}", nmapout::EXT_GREP),
            nmapout::grepable(all, started, finished, list_closed),
        ));
        jobs.push((
            format!("{base}.{}", nmapout::EXT_XML),
            nmapout::xml(all, started, finished, list_closed),
        ));
    }

    for (path, body) in jobs {
        if path == "-" {
            print!("{body}");
        } else {
            std::fs::write(&path, body).map_err(|e| format!("cannot write {path}: {e}"))?;
            if !args.terse() {
                eprintln!("truemap: wrote {path}");
            }
        }
    }
    Ok(())
}

/// Run the raw SYN fingerprint on a bounded sample plus the anchors.
///
/// Bounded deliberately: the layer-4 test only needs enough ports to establish
/// whether SYN-ACKs carry a real stack's fingerprint, and a raw burst across 65535
/// ports is both loud and lossy.
async fn l4_probe(ip: Ipv4Addr, port_list: &[u16]) -> Option<synack::L4Verdict> {
    let mut sample: Vec<u16> = ports::ANCHORS.to_vec();
    for &p in port_list.iter().take(400) {
        if !sample.contains(&p) {
            sample.push(p);
        }
    }
    let probed = sample.len();
    let res =
        tokio::task::spawn_blocking(move || synack::syn_scan(ip, &sample, Duration::from_secs(4)))
            .await;
    match res {
        Ok(Ok(acks)) => Some(synack::discriminate(&acks, probed, synack::MAX_REAL)),
        Ok(Err(e)) => Some(synack::L4Verdict {
            probed,
            answered: 0,
            real: vec![],
            tarpit: vec![],
            note: format!("raw SYN scan failed: {e}"),
            usable: false,
        }),
        Err(e) => Some(synack::L4Verdict {
            probed,
            answered: 0,
            real: vec![],
            tarpit: vec![],
            note: format!("raw SYN scan task failed: {e}"),
            usable: false,
        }),
    }
}
