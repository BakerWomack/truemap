//! A rustscan-compatible command line.
//!
//! The flags, defaults and the `-- <nmap args>` hand-off are deliberately the same
//! as rustscan's, so an existing command works unchanged. Where truemap differs it
//! differs loudly — see `DELIBERATE DIFFERENCES` below — because a flag that is
//! accepted and quietly ignored is worse than one that is missing.
//!
//! DELIBERATE DIFFERENCES FROM RUSTSCAN
//!
//! * `--tries` defaults to **2**, not 1. truemap's liveness verdict turns on telling
//!   a refused port from a dropped one, and a single try makes ordinary packet loss
//!   look like a drop. One extra try is cheap; a wrong "NO RESPONSE" is not.
//! * `--udp` is **accepted and refused**, with a message. truemap is TCP-only. The
//!   flag exists so a rustscan command that asks for UDP fails loudly instead of
//!   silently scanning TCP and reporting it as a UDP result.
//! * `--scan-order` is honoured, but the likely-service ports are **always probed
//!   first** regardless. That is a correctness requirement, not a preference: on a
//!   host that answers everything the sweep bails out early, and a purely random
//!   order can bail before reaching port 22. See `sweep::sweep`.
//! * There is **no config file**, so rustscan's `-c/--config-path` and
//!   `-n/--no-config` are not implemented rather than stubbed.
//! * nmap is handed the ports truemap **proved**, not everything that answered. On a
//!   SYN-proxied host that is the difference between nmap scanning 2 ports and 65535.
//! * `-iL <file>` is borrowed from nmap, not rustscan, because a scope document is a
//!   file of IPs and CIDRs and pasting a thousand of them onto a command line is not
//!   a workflow. It cannot be a clap short flag -- see `rewrite_nmap_flags`.
//! * `-p-` means every port, as in nmap. rustscan spells this `-r 1-65535`, which
//!   still works; so do open-ended ranges (`-p1-`, `-p-1024`).
//! * `-x/--exclude-addresses` excludes by **address**, not by string-matching the
//!   spec you typed. rustscan compares strings, so `-a 10.0.0.0/24 -x 10.0.0.5`
//!   scans 10.0.0.5 anyway. With `-iL` that is actively unsafe: a list of CIDRs
//!   minus a few out-of-scope hosts is the normal shape of a scoped scan.

use clap::{ArgAction, Parser, ValueEnum};

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum ScanOrder {
    /// Ascending port order.
    Serial,
    /// Shuffled, which keeps the running open-ratio an unbiased sample.
    Random,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum Scripts {
    /// Hand the proven ports to nmap (the default, as in rustscan).
    Default,
    /// Never run nmap, even if args were given after `--`.
    None,
}

#[derive(Parser, Debug)]
#[command(
    name = "truemap",
    version,
    about = "Fast TCP scanner that proves which \"open\" ports are real services",
    long_about = "A rustscan-compatible port scanner that does not take a SYN-ACK for an \
                  answer. It calibrates against known-closed control ports on each host, \
                  sweeps with a batched async connect scan, then proves every candidate at \
                  the application layer — and hands nmap only the ports it proved.",
    after_help = "EXAMPLES:\n  \
        truemap 10.0.0.5                        scan the top 1000 ports\n  \
        truemap -a 10.0.0.0/24 -r 1-1000        a range across a CIDR\n  \
        truemap 10.0.0.5 -p 22,80,443 -g        greppable, specific ports\n  \
        truemap 10.0.0.5 -r 1-65535 -- -A -sC   proven ports -> nmap\n  \
        truemap -iL scope.txt -r 1-1000         targets from a file, one IP or CIDR per line\n  \
        truemap -iL scope.txt -x 10.0.0.5       ... minus one out-of-scope address\n  \
        truemap 10.0.0.5 -p-                    every port, 1-65535\n  \
        truemap 10.0.0.5 --l4 --deep            every answering port, plus the raw SYN-ACK test"
)]
pub struct Args {
    /// Comma-separated IPs, CIDRs or hostnames. Positional, as in rustscan 1.x.
    #[arg(value_name = "IPS_OR_HOSTS", value_delimiter = ',')]
    pub positional: Vec<String>,

    /// Comma-separated IPs, CIDRs or hostnames. The rustscan 2.x spelling.
    #[arg(short = 'a', long, value_delimiter = ',', value_name = "ADDRESSES")]
    pub addresses: Vec<String>,

    /// Read targets from a file: one IP, CIDR or hostname per line. `-` means stdin.
    ///
    /// Also spelled `-iL <FILE>`, as in nmap. `#` starts a comment; blank lines are
    /// skipped; a malformed entry fails the whole file before anything is scanned.
    #[arg(long = "input-list", visible_alias = "iL", value_name = "FILE")]
    pub input_list: Vec<String>,

    /// Addresses to skip. Matched by address, so excluding a host inside a CIDR works.
    #[arg(short = 'x', long, value_delimiter = ',', value_name = "ADDRESSES")]
    pub exclude_addresses: Vec<String>,

    /// Comma-separated ports: 80,443,8080. A range works too, and `-p-` means every port.
    #[arg(short = 'p', long, value_delimiter = ',', value_name = "PORTS")]
    pub ports: Vec<u16>,

    /// A port range: 1-65535, or `all`, `top1000`, `anchors`, `-`. Open ends: `-1024`, `100-`.
    #[arg(short = 'r', long, value_name = "RANGE")]
    pub range: Option<String>,

    /// Scan the 1000 most common ports (the default when no ports are given).
    #[arg(long)]
    pub top: bool,

    /// Ports to skip.
    #[arg(short = 'e', long, value_delimiter = ',', value_name = "PORTS")]
    pub exclude_ports: Vec<u16>,

    /// Concurrent connections. Capped at the file-descriptor limit.
    #[arg(short = 'b', long, default_value_t = 4500, value_name = "BATCH_SIZE")]
    pub batch_size: usize,

    /// Milliseconds before a port is assumed closed.
    #[arg(short = 't', long, default_value_t = 1500, value_name = "TIMEOUT")]
    pub timeout: u64,

    /// Attempts per port. 2 by default — see the note in cli.rs.
    #[arg(long, default_value_t = 2, value_name = "TRIES")]
    pub tries: usize,

    /// Raise RLIMIT_NOFILE to this value before scanning.
    #[arg(short = 'u', long, value_name = "ULIMIT")]
    pub ulimit: Option<u64>,

    /// Port order. The likely-service ports always lead regardless; see cli.rs.
    #[arg(long, value_enum, default_value_t = ScanOrder::Serial, value_name = "SCAN_ORDER")]
    pub scan_order: ScanOrder,

    /// Whether to hand the proven ports to nmap.
    #[arg(long, value_enum, default_value_t = Scripts::Default, value_name = "SCRIPTS")]
    pub scripts: Scripts,

    /// Only print `ip -> [ports]`. No art, no decoration.
    #[arg(short = 'g', long, visible_alias = "grep")]
    pub greppable: bool,

    /// Same as --greppable. The rustscan 1.x spelling.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// No ASCII art and no large blocks of text, for screen readers.
    #[arg(long)]
    pub accessible: bool,

    /// TCP only. Present so a UDP request fails loudly instead of being ignored.
    #[arg(long)]
    pub udp: bool,

    /// Disable colour.
    #[arg(long)]
    pub no_color: bool,

    // ---- truemap's own flags, beyond rustscan ----
    /// Known-closed control ports used to learn what "closed" looks like per host.
    #[arg(long, default_value_t = crate::calib::DEFAULT_CONTROLS, value_name = "N")]
    pub controls: usize,

    /// Prove EVERY answering port, not just the likely-service ones.
    #[arg(long)]
    pub deep: bool,

    /// Stop enumerating after this many answering ports on an indiscriminate host.
    #[arg(long, default_value_t = 2000, value_name = "N")]
    pub bail_after: usize,

    /// Concurrency for the application-layer proving phase.
    #[arg(long, default_value_t = 200, value_name = "N")]
    pub adjudicate_batch: usize,

    /// Also run the raw SYN-ACK window/options tarpit test. Needs CAP_NET_RAW.
    #[arg(long)]
    pub l4: bool,

    /// Machine-readable full output, including why each port was rejected.
    #[arg(long)]
    pub json: bool,

    /// List the fabricated ports individually instead of collapsing them.
    #[arg(long)]
    pub show_fakes: bool,

    /// Print the banner even in greppable mode.
    #[arg(long, action = ArgAction::SetTrue, hide = true)]
    pub force_banner: bool,

    /// Arguments passed to nmap, after `--`. truemap appends `-Pn -p <proven ports>`.
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

impl Args {
    /// The target specs written on the command line: positional and `-a` alike.
    ///
    /// The spec-string exclusion below is a convenience for the exact-match case.
    /// The authoritative exclusion happens by ADDRESS in `main`, which is the only
    /// form that can cover a host sitting inside a CIDR.
    pub fn targets(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in self.positional.iter().chain(self.addresses.iter()) {
            let t = t.trim();
            if !t.is_empty() && !out.iter().any(|x| x == t) {
                out.push(t.to_string());
            }
        }
        out.retain(|t| !self.exclude_addresses.iter().any(|x| x.trim() == t));
        out
    }

    /// Every target spec: the command line, plus every entry of every `-iL` file.
    ///
    /// Fallible, because reading a list file is, and it fails rather than scanning
    /// the part that parsed. A list file is normally a scope document; quietly
    /// proceeding with half of it is how an operator comes to believe a host was
    /// examined and cleared when it was never looked at.
    pub fn target_specs(&self) -> Result<Vec<String>, String> {
        let mut out = self.targets();
        for f in &self.input_list {
            for s in crate::target::read_target_list(f)? {
                if !out.iter().any(|x| *x == s) {
                    out.push(s);
                }
            }
        }
        out.retain(|t| !self.exclude_addresses.iter().any(|x| x.trim() == t));
        Ok(out)
    }

    /// The port set: `-p`, `-r`, `--top`, or the top-1000 default, minus `-e`.
    pub fn port_list(&self) -> Result<Vec<u16>, String> {
        let mut ports: Vec<u16> = Vec::new();
        if let Some(r) = &self.range {
            ports.extend(crate::target::parse_ports(r)?);
        }
        ports.extend(self.ports.iter().copied());
        if self.top || ports.is_empty() {
            ports.extend(crate::ports::TOP_1000.iter().copied());
        }
        ports.sort_unstable();
        ports.dedup();
        ports.retain(|p| !self.exclude_ports.contains(p));
        if ports.is_empty() {
            return Err("every port was excluded; nothing left to scan".into());
        }
        Ok(ports)
    }

    /// Terse output: no art, no tables, just results.
    pub fn terse(&self) -> bool {
        self.greppable || self.quiet || self.json
    }

    pub fn use_color(&self) -> bool {
        !self.no_color && !self.accessible && !self.terse()
    }

    /// Should nmap run on the proven ports?
    pub fn run_nmap(&self) -> bool {
        self.scripts == Scripts::Default && !self.command.is_empty()
    }
}

/// Rewrite nmap's `-iL` and `-p-` spellings into flags clap can express.
///
/// Neither can be a clap short option, for the same reason. A short option that
/// takes a value consumes the rest of its token, so `short = 'i'` would make
/// `-iL scope.txt` parse as `-i` with the value `"L"` -- leaving `scope.txt` over as
/// a POSITIONAL argument, i.e. a TARGET. truemap would resolve a filename as a
/// hostname and scan whatever came back. Likewise `-p-` reaches clap as `-p` with the
/// value `"-"`, which is not a u16. Silently scanning the wrong thing is far worse
/// than rejecting a flag, so these are rewritten before parsing and `-i` alone is
/// deliberately never defined.
///
/// Ports are unsigned, so a `-` inside a `-p` value can only mean a range; that is
/// what makes routing those to `--range` unambiguous. `-p 22,80` is untouched.
///
/// Nothing after `--` is rewritten. Those arguments belong to nmap, which has its own
/// `-iL` and `-p-`, and must receive them verbatim.
pub fn rewrite_nmap_flags<I: IntoIterator<Item = String>>(argv: I) -> Vec<String> {
    let v: Vec<String> = argv.into_iter().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < v.len() {
        let a = v[i].clone();
        if a == "--" {
            out.extend_from_slice(&v[i..]);
            break;
        }
        // -- target list: -iL FILE, -iL=FILE, -iLFILE ------------------------
        if a == "-iL" {
            // `--flag value` would let clap read a value starting with '-' as a flag,
            // and `-iL -` (stdin) is exactly that. One `--flag=value` token cannot be
            // misread, so the value is attached here and below.
            // Never consume `--` as the filename: that would eat the nmap separator
            // and leave clap trying to read a file called "--".
            if let Some(n) = v.get(i + 1).filter(|n| *n != "--") {
                out.push(format!("--input-list={n}"));
                i += 2;
            } else {
                out.push("--input-list".to_string());
                i += 1;
            }
            continue;
        }
        if let Some(rest) = a.strip_prefix("-iL=").or_else(|| a.strip_prefix("-iL")) {
            out.push(format!("--input-list={rest}"));
            i += 1;
            continue;
        }
        // -- port ranges spelled nmap's way ----------------------------------
        if let Some(spec) = port_flag_range(&a, v.get(i + 1).map(String::as_str)) {
            out.push(format!("--range={}", spec.range));
            i += 1 + usize::from(spec.consumed_next);
            continue;
        }
        out.push(a);
        i += 1;
    }
    out
}

struct RangeRewrite {
    range: String,
    consumed_next: bool,
}

/// If this argument is a `-p`/`--ports` carrying a RANGE, give back the range spec.
///
/// `None` for a plain port list, which `-p` already handles, and for anything that is
/// not a ports flag.
fn port_flag_range(arg: &str, next: Option<&str>) -> Option<RangeRewrite> {
    let attached = |s: &str| {
        Some(RangeRewrite {
            range: if s == "-" { "all".to_string() } else { s.to_string() },
            consumed_next: false,
        })
    };
    // Attached value: -p-, -p1-1000, -p-1024, --ports=1-
    if arg == "-p-" {
        return attached("-");
    }
    for pre in ["-p", "--ports="] {
        if let Some(rest) = arg.strip_prefix(pre) {
            if !rest.is_empty() && rest.contains('-') {
                return attached(rest);
            }
        }
    }
    // Separated value: -p - / -p 1-1000 / --ports 1-
    if arg == "-p" || arg == "--ports" {
        let n = next?;
        if n == "-" {
            return Some(RangeRewrite { range: "all".to_string(), consumed_next: true });
        }
        if n.contains('-') && !n.starts_with("--") {
            return Some(RangeRewrite { range: n.to_string(), consumed_next: true });
        }
    }
    None
}

/// Raise RLIMIT_NOFILE, as rustscan's `-u` does. Returns the limit now in force.
pub fn set_ulimit(requested: Option<u64>) -> (u64, Option<String>) {
    let current = crate::sweep::fd_limit().unwrap_or(1024) as u64;
    let Some(want) = requested else {
        return (current, None);
    };
    if want <= current {
        return (current, None);
    }
    match crate::sweep::raise_fd_limit(want) {
        Ok(now) => (now, None),
        Err(hard) => (
            current,
            Some(format!(
                "could not raise the open-file limit to {want}: the hard limit is {hard}. \
                 Scanning with {current}. Raise the hard limit as root, or lower --batch-size."
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Args {
        Args::parse_from(std::iter::once("truemap").chain(args.iter().copied()))
    }

    #[test]
    fn a_bare_rustscan_command_works_unchanged() {
        let a = parse(&["127.0.0.1"]);
        assert_eq!(a.targets(), vec!["127.0.0.1"]);
        assert_eq!(a.port_list().unwrap().len(), 1000, "defaults to the top 1000");
        assert_eq!(a.batch_size, 4500, "rustscan's default batch size");
        assert_eq!(a.timeout, 1500, "rustscan's default timeout");
    }

    #[test]
    fn both_target_spellings_are_accepted_and_merged() {
        let a = parse(&["-a", "10.0.0.1,10.0.0.2", "10.0.0.3"]);
        let t = a.targets();
        assert!(t.contains(&"10.0.0.1".to_string()));
        assert!(t.contains(&"10.0.0.2".to_string()));
        assert!(t.contains(&"10.0.0.3".to_string()), "positional form still works");
    }

    #[test]
    fn exclusions_apply_to_both_ports_and_addresses() {
        let a = parse(&["-a", "10.0.0.1,10.0.0.2", "-x", "10.0.0.2"]);
        assert_eq!(a.targets(), vec!["10.0.0.1"]);
        let b = parse(&["1.2.3.4", "-r", "20-25", "-e", "22,23"]);
        assert_eq!(b.port_list().unwrap(), vec![20, 21, 24, 25]);
    }

    #[test]
    fn range_and_port_list_combine_and_dedupe() {
        let a = parse(&["1.2.3.4", "-r", "80-82", "-p", "81,443"]);
        assert_eq!(a.port_list().unwrap(), vec![80, 81, 82, 443]);
    }

    #[test]
    fn excluding_everything_is_an_error_not_an_empty_scan() {
        let a = parse(&["1.2.3.4", "-p", "80", "-e", "80"]);
        assert!(a.port_list().is_err(), "an empty scan must not be silently run");
    }

    #[test]
    fn the_nmap_handoff_is_parsed_from_after_the_double_dash() {
        let a = parse(&["1.2.3.4", "--", "-A", "-sC"]);
        assert_eq!(a.command, vec!["-A", "-sC"]);
        assert!(a.run_nmap());
        // --scripts none must win over args being present.
        let b = parse(&["1.2.3.4", "--scripts", "none", "--", "-A"]);
        assert!(!b.run_nmap(), "--scripts none must suppress the hand-off");
        // No args after -- means no nmap.
        assert!(!parse(&["1.2.3.4"]).run_nmap());
    }

    #[test]
    fn greppable_quiet_and_json_all_imply_terse_and_no_colour() {
        for f in ["-g", "-q", "--json", "--greppable", "--grep"] {
            let a = parse(&["1.2.3.4", f]);
            assert!(a.terse(), "{f} must be terse");
            assert!(!a.use_color(), "{f} must not colour");
        }
        assert!(!parse(&["1.2.3.4", "--accessible"]).use_color());
    }

    #[test]
    fn tries_defaults_higher_than_rustscan_on_purpose() {
        // The refused-vs-dropped verdict depends on not mistaking loss for a drop.
        assert_eq!(parse(&["1.2.3.4"]).tries, 2);
        assert_eq!(parse(&["1.2.3.4", "--tries", "1"]).tries, 1);
    }

    #[test]
    fn scan_order_and_scripts_accept_rustscans_spellings() {
        assert_eq!(parse(&["1.2.3.4", "--scan-order", "random"]).scan_order, ScanOrder::Random);
        assert_eq!(parse(&["1.2.3.4", "--scan-order", "serial"]).scan_order, ScanOrder::Serial);
        assert_eq!(parse(&["1.2.3.4", "--scripts", "none"]).scripts, Scripts::None);
    }

    fn rw(args: &[&str]) -> Vec<String> {
        rewrite_nmap_flags(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn dash_i_l_is_rewritten_in_all_three_nmap_spellings() {
        for form in [
            vec!["-iL", "scope.txt"],
            vec!["-iL=scope.txt"],
            vec!["-iLscope.txt"],
        ] {
            assert_eq!(rw(&form), vec!["--input-list=scope.txt"], "{form:?}");
        }
        // `-` is stdin, and must survive as a VALUE rather than being read as a flag.
        assert_eq!(rw(&["-iL", "-"]), vec!["--input-list=-"]);
        let a = Args::parse_from(
            std::iter::once("truemap".to_string()).chain(rw(&["-iL", "-"])),
        );
        assert_eq!(a.input_list, vec!["-"], "-iL - must mean stdin");
    }

    #[test]
    fn the_filename_after_dash_i_l_never_becomes_a_target() {
        // The trap this rewrite exists for. Declaring `short = 'i'` would parse
        // `-iL scope.txt` as `-i` with the value "L", leaving scope.txt as a
        // POSITIONAL argument -- truemap would resolve a filename as a hostname and
        // scan whatever came back.
        let a = Args::parse_from(std::iter::once("truemap".to_string()).chain(rw(&[
            "-iL",
            "scope.txt",
        ])));
        assert_eq!(a.input_list, vec!["scope.txt"]);
        assert!(
            a.positional.is_empty(),
            "the list FILE must never be left over as a target: {:?}",
            a.positional
        );
    }

    #[test]
    fn dash_p_dash_means_every_port() {
        let a = Args::parse_from(
            std::iter::once("truemap".to_string()).chain(rw(&["1.2.3.4", "-p-"])),
        );
        assert_eq!(a.port_list().unwrap().len(), 65535);
        // The separated spelling too.
        let b = Args::parse_from(
            std::iter::once("truemap".to_string()).chain(rw(&["1.2.3.4", "-p", "-"])),
        );
        assert_eq!(b.port_list().unwrap().len(), 65535);
    }

    #[test]
    fn a_range_given_to_dash_p_is_routed_to_the_range_parser() {
        // `-p 1-1000` is an error in rustscan (its -p is a list, -r is the range).
        // Ports are unsigned, so a '-' in a -p value can only mean a range.
        for form in [vec!["1.2.3.4", "-p1-5"], vec!["1.2.3.4", "-p", "1-5"]] {
            let a = Args::parse_from(
                std::iter::once("truemap".to_string()).chain(rw(&form)),
            );
            assert_eq!(a.port_list().unwrap(), vec![1, 2, 3, 4, 5], "{form:?}");
        }
        // Open-ended, as nmap writes it.
        let a = Args::parse_from(
            std::iter::once("truemap".to_string()).chain(rw(&["1.2.3.4", "-p-3"])),
        );
        assert_eq!(a.port_list().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn a_plain_port_list_is_left_alone_by_the_rewrite() {
        assert_eq!(rw(&["-p", "22,80"]), vec!["-p", "22,80"]);
        assert_eq!(rw(&["-p22"]), vec!["-p22"]);
        let a = Args::parse_from(
            std::iter::once("truemap".to_string()).chain(rw(&["1.2.3.4", "-p", "22,80"])),
        );
        assert_eq!(a.port_list().unwrap(), vec![22, 80]);
    }

    #[test]
    fn nothing_after_the_double_dash_is_rewritten() {
        // Those arguments are nmap's, and nmap has its own -iL and -p-.
        assert_eq!(
            rw(&["1.2.3.4", "--", "-iL", "theirs.txt", "-p-"]),
            vec!["1.2.3.4", "--", "-iL", "theirs.txt", "-p-"]
        );
        let a = Args::parse_from(std::iter::once("truemap".to_string()).chain(rw(&[
            "1.2.3.4", "--", "-iL", "theirs.txt",
        ])));
        assert_eq!(a.command, vec!["-iL", "theirs.txt"]);
        assert!(a.input_list.is_empty(), "nmap's -iL must not become truemap's");
    }

    #[test]
    fn a_valueless_list_flag_does_not_swallow_the_nmap_separator() {
        // `-iL --` must not turn `--` into the filename; clap should report the
        // missing value instead.
        assert_eq!(rw(&["-iL", "--", "-sV"]), vec!["--input-list", "--", "-sV"]);
        assert!(Args::try_parse_from(
            std::iter::once("truemap".to_string()).chain(rw(&["-iL", "--", "-sV"]))
        )
        .is_err());
    }

    #[test]
    fn the_long_spellings_of_the_list_flag_both_work() {
        for f in ["--input-list", "--iL"] {
            let a = parse(&[f, "scope.txt"]);
            assert_eq!(a.input_list, vec!["scope.txt"], "{f}");
        }
    }

    #[test]
    fn top_is_accepted_explicitly() {
        assert_eq!(parse(&["1.2.3.4", "--top"]).port_list().unwrap().len(), 1000);
    }
}
