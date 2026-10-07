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
        truemap 10.0.0.5 --l4 --deep            every answering port, plus the raw SYN-ACK test"
)]
pub struct Args {
    /// Comma-separated IPs, CIDRs or hostnames. Positional, as in rustscan 1.x.
    #[arg(value_name = "IPS_OR_HOSTS", value_delimiter = ',')]
    pub positional: Vec<String>,

    /// Comma-separated IPs, CIDRs or hostnames. The rustscan 2.x spelling.
    #[arg(short = 'a', long, value_delimiter = ',', value_name = "ADDRESSES")]
    pub addresses: Vec<String>,

    /// Addresses to skip.
    #[arg(short = 'x', long, value_delimiter = ',', value_name = "ADDRESSES")]
    pub exclude_addresses: Vec<String>,

    /// Comma-separated ports. Example: 80,443,8080
    #[arg(short = 'p', long, value_delimiter = ',', value_name = "PORTS")]
    pub ports: Vec<u16>,

    /// A port range, start-end. Example: 1-65535
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
    /// All target specs, from the positional form and `-a` alike, minus `-x`.
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

    #[test]
    fn top_is_accepted_explicitly() {
        assert_eq!(parse(&["1.2.3.4", "--top"]).port_list().unwrap().len(), 1000);
    }
}
