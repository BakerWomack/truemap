//! An nmap-compatible command line.
//!
//! The single-letter flags follow **nmap**, which is what most people have in their
//! fingers. Where nmap and rustscan disagree on a letter, nmap wins and rustscan's
//! meaning keeps its long form:
//!
//! | letter | nmap, and so truemap | rustscan's meaning, now long-only |
//! |--------|----------------------|-----------------------------------|
//! | `-r`   | scan ports sequentially (no value) | `--range <SPEC>` |
//! | `-e`   | interface            | `--exclude-ports <LIST>` |
//! | `-b`   | FTP bounce           | `--batch-size <N>` |
//! | `-g`   | source port          | `--greppable` (also `-q`) |
//!
//! `-a`, `-x`, `-t`, `-u` and `-q` are untouched: nmap does not use those letters.
//! A rustscan command that uses a reassigned short flag now FAILS rather than doing
//! something different, which is the only safe way to make this change.
//!
//! Flags truemap cannot honour are accepted and REFUSED with the reason, never
//! accepted and ignored: a flag that is silently dropped makes the operator believe
//! a constraint was applied. `-e`, `-b` and `-g` all need control of the socket
//! before `connect()`, which this connect scanner does not take, so they say so.
//!
//! DELIBERATE DIFFERENCES FROM BOTH
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
//! * In `-oN`/`-oG`/`-oX`, a port that answered but could not be shown to run a
//!   service is reported **closed**, where nmap reports it open. See `nmapout`.
//! * `-iR <num>` (nmap's random-target picker) is **not implemented**, deliberately.
//!   This tool is used on scoped engagements; a flag whose job is to generate
//!   targets nobody authorised has no business here.
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
        truemap -a 10.0.0.0/24 -p 1-1000        a port range across a CIDR\n  \
        truemap 10.0.0.5 -p 22,80,443 -q        greppable, specific ports\n  \
        truemap 10.0.0.5 -p- -oA scan           every port; output in all three formats\n  \
        truemap -iL scope.txt -F --open         a scope file, fast scan, proven ports only\n  \
        truemap -iL scope.txt -x 10.0.0.5       ... minus one out-of-scope address\n  \
        truemap 10.0.0.5 -p 1-65535 -- -A -sC   proven ports -> nmap\n  \
        truemap 10.0.0.5 --l4 --deep            every answering port, plus the raw SYN-ACK test\n\
\n\
nmap SHORT SPELLINGS (rewritten before parsing, so they are absent from the list above):\n  \
        -iL FILE = --input-list    -oN FILE = --output-normal    -oX FILE = --output-xml\n  \
        -p-      = --range all     -oG FILE = --output-grep      -oA BASE = --output-all\n  \
        -Pn      = accepted no-op\n\
\n\
REASSIGNED FROM RUSTSCAN -- nmap wins these letters:\n  \
        -r = sequential order (was --range)        -b = ftp bounce (was --batch-size)\n  \
        -e = interface (was --exclude-ports)       -g = source port (was --greppable)"
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
    ///
    /// `--exclude` is nmap's spelling of the same thing.
    #[arg(
        short = 'x',
        long,
        visible_alias = "exclude",
        value_delimiter = ',',
        value_name = "ADDRESSES"
    )]
    pub exclude_addresses: Vec<String>,

    /// Comma-separated ports: 80,443,8080. A range works too, and `-p-` means every port.
    #[arg(short = 'p', long, value_delimiter = ',', value_name = "PORTS")]
    pub ports: Vec<u16>,

    /// A port range: 1-65535, or `all`, `top1000`, `anchors`, `-`. Open ends: `-1024`, `100-`.
    ///
    /// Long-only: nmap's `-r` means sequential order, so it is `--sequential` here.
    #[arg(long, value_name = "RANGE")]
    pub range: Option<String>,

    /// Scan ports sequentially — do not randomise. nmap's `-r`.
    #[arg(short = 'r', long = "sequential")]
    pub sequential: bool,

    /// Fast mode: the 100 most common ports. nmap's `-F`.
    #[arg(short = 'F', long)]
    pub fast: bool,

    /// Scan the N most common ports. nmap's `--top-ports`.
    #[arg(long, value_name = "N")]
    pub top_ports: Option<usize>,

    /// Scan the 1000 most common ports (the default when no ports are given).
    #[arg(long)]
    pub top: bool,

    /// Ports to skip. Long-only: nmap's `-e` is the interface.
    #[arg(long, value_delimiter = ',', value_name = "PORTS")]
    pub exclude_ports: Vec<u16>,

    /// Exclusions from a file, one entry per line. nmap's `--excludefile`.
    #[arg(long = "excludefile", value_name = "FILE")]
    pub exclude_file: Option<String>,

    /// Concurrent connections. Capped at the fd limit. Long-only: nmap's `-b` is
    /// the FTP bounce host.
    #[arg(long, default_value_t = 4500, value_name = "BATCH_SIZE")]
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

    /// Only print `ip -> [ports]`. No art, no decoration. Long-only plus `-q`:
    /// nmap's `-g` is the source port.
    #[arg(long, visible_alias = "grep")]
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

    // ---- nmap-shaped output files. The short spellings -oN/-oG/-oX/-oA are
    // rewritten to these; see rewrite_nmap_flags. ----
    /// `-oN <FILE>`: write nmap's normal layout to a file. `-` is stdout.
    #[arg(long = "output-normal", value_name = "FILE")]
    pub output_normal: Option<String>,

    /// `-oG <FILE>`: write nmap's grepable layout to a file. `-` is stdout.
    #[arg(long = "output-grep", value_name = "FILE")]
    pub output_grep: Option<String>,

    /// `-oX <FILE>`: write nmap-shaped XML to a file. `-` is stdout.
    #[arg(long = "output-xml", value_name = "FILE")]
    pub output_xml: Option<String>,

    /// `-oA <BASE>`: write all three formats as BASE.nmap/.gnmap/.xml.
    #[arg(long = "output-all", value_name = "BASE")]
    pub output_all: Option<String>,

    /// Show only ports that were proved to run a service. nmap's `--open`.
    #[arg(long)]
    pub open: bool,

    /// Show why each port got its verdict. nmap's `--reason`.
    #[arg(long)]
    pub reason: bool,

    /// Increase verbosity: `-v` lists suppressed ports, `-vv` adds the calibration.
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Increase debugging output on stderr. nmap's `-d`.
    #[arg(short = 'd', long, action = ArgAction::Count)]
    pub debug: u8,

    /// Never resolve hostnames: a hostname target becomes an error. nmap's `-n`.
    #[arg(short = 'n', long = "no-dns")]
    pub no_dns: bool,

    /// Always resolve. nmap's `-R`; truemap's default, and it does no reverse DNS.
    #[arg(short = 'R', long = "always-dns")]
    pub always_dns: bool,

    /// `-Pn`: treat every host as online. Accepted no-op — truemap never pings.
    #[arg(long = "pn", hide = true)]
    pub pn: bool,

    // ---- accepted and REFUSED, with the reason. See the header note. ----
    /// Source interface (nmap's `-e`). Refused: see the message.
    #[arg(short = 'e', long = "interface", value_name = "IFACE")]
    pub interface: Option<String>,

    /// FTP bounce (nmap's `-b`). Refused: see the message.
    #[arg(short = 'b', long = "ftp-bounce", value_name = "HOST")]
    pub ftp_bounce: Option<String>,

    /// Source port (nmap's `-g`). Refused: see the message.
    #[arg(short = 'g', long = "source-port", value_name = "PORT")]
    pub source_port: Option<u16>,

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

    /// The port set: `-p`, `--range`, `-F`, `--top-ports`, `--top`, or the
    /// top-1000 default, minus `--exclude-ports`.
    pub fn port_list(&self) -> Result<Vec<u16>, String> {
        let mut ports: Vec<u16> = Vec::new();
        if let Some(r) = &self.range {
            ports.extend(crate::target::parse_ports(r)?);
        }
        ports.extend(self.ports.iter().copied());
        if let Some(n) = self.top_ports {
            if n == 0 {
                return Err("--top-ports 0 would scan nothing".into());
            }
            let have = crate::ports::TOP_1000.len();
            if n > have {
                return Err(format!(
                    "--top-ports {n}: truemap ranks only the top {have} ports. Use \
                     `-p-` for all 65535, or --top-ports {have}."
                ));
            }
            ports.extend(crate::ports::TOP_1000.iter().copied().take(n));
        }
        if self.fast {
            ports.extend(crate::ports::TOP_1000.iter().copied().take(100));
        }
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
        self.greppable || self.quiet || self.json || self.stdout_is_a_report()
    }

    /// Is a report format being written to stdout? Then the human view must not
    /// also go there, or the file is corrupted by the banner and the tables.
    pub fn stdout_is_a_report(&self) -> bool {
        [&self.output_normal, &self.output_grep, &self.output_xml]
            .iter()
            .any(|o| o.as_deref() == Some("-"))
    }

    /// The port order actually used. `-r` forces sequential, as in nmap.
    pub fn order(&self) -> ScanOrder {
        if self.sequential {
            ScanOrder::Serial
        } else {
            self.scan_order
        }
    }

    /// Flags truemap accepts so they fail loudly, rather than being ignored.
    ///
    /// Each needs the socket configured before `connect()`. truemap hands connect
    /// to tokio and never holds the raw socket on the application-layer path, so
    /// honouring these would mean rebuilding that path -- and a scan that silently
    /// ignored `-e eth1` would report results for the wrong interface.
    pub fn refusals(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(i) = &self.interface {
            out.push(format!(
                "-e/--interface {i}: truemap cannot bind the scan to an interface. Its \
                 connect path does not own the socket before connect(), so this would \
                 have to be ignored -- and a scan that quietly used the wrong interface \
                 is worse than one that refuses. Route with `ip route`/a netns instead."
            ));
        }
        if let Some(b) = &self.ftp_bounce {
            out.push(format!(
                "-b/--ftp-bounce {b}: not implemented. An FTP bounce scan is a different \
                 technique -- it makes a third-party FTP server do the scanning -- and \
                 truemap's whole method is proving a service by talking to it directly."
            ));
        }
        if let Some(g) = &self.source_port {
            out.push(format!(
                "-g/--source-port {g}: truemap cannot set the source port, for the same \
                 reason as -e. Nothing would have bound it, so the scan would have gone \
                 out from an ephemeral port while you believed otherwise."
            ));
        }
        out
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
pub fn rewrite_nmap_flags<I: IntoIterator<Item = String>>(argv: I) -> Rewritten {
    let v: Vec<String> = argv.into_iter().collect();
    let mut out: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
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
        // -- output files: -oN/-oG/-oX/-oA FILE, or with the value attached ---
        if let Some((flag, rest)) = output_flag(&a) {
            if rest.is_empty() {
                match v.get(i + 1).filter(|n| *n != "--") {
                    Some(n) => {
                        out.push(format!("--{flag}={n}"));
                        i += 2;
                    }
                    None => {
                        out.push(format!("--{flag}"));
                        i += 1;
                    }
                }
            } else {
                out.push(format!("--{flag}={rest}"));
                i += 1;
            }
            continue;
        }
        // -- accepted no-op ---------------------------------------------------
        if a == "-Pn" || a == "-PN" {
            out.push("--pn".to_string());
            i += 1;
            continue;
        }
        // -- a rustscan habit that must not be guessed at ---------------------
        // `-r 1-1000` used to be a port range and is now nmap's valueless -r, so
        // clap would take `1-1000` as a POSITIONAL -- a target. truemap would then
        // try to resolve a port range as a hostname and scan whatever came back,
        // which is the one outcome worse than an error.
        if let Some(e) = reassigned_letter_misuse(&a, v.get(i + 1).map(String::as_str)) {
            errors.push(e);
            out.push(a);
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
    Rewritten { argv: out, errors }
}

/// The rewritten argument vector, plus anything that must stop the run.
pub struct Rewritten {
    pub argv: Vec<String>,
    pub errors: Vec<String>,
}

/// Catch a rustscan command that would now mean something else.
///
/// Four letters changed hands (`-r`, `-e`, `-b`, `-g`). Three of them now take a
/// value and so merely get refused, but `-r` takes none, which means its old
/// argument silently becomes a target. Each case names the long flag that still
/// does what the author meant, because "unexpected argument" does not.
fn reassigned_letter_misuse(arg: &str, next: Option<&str>) -> Option<String> {
    let n = next?;
    let looks_like_ports = |s: &str| {
        matches!(s, "all" | "top1000" | "anchors")
            || (!s.is_empty()
                && s.bytes().all(|b| b.is_ascii_digit() || b == b',' || b == b'-'))
    };
    match arg {
        "-r" if looks_like_ports(n) => Some(format!(
            "-r takes no value: in nmap's CLI it means \"scan ports sequentially\". You \
             passed {n:?}, which is a port spec, so it would have been read as a TARGET \
             and resolved as a hostname. Use `-p {n}` or `--range {n}`; `-r` alone still \
             forces sequential order."
        )),
        "-e" if looks_like_ports(n) => Some(format!(
            "-e is the interface now, as in nmap, and {n:?} is a port list. Use \
             `--exclude-ports {n}`."
        )),
        "-b" if n.bytes().all(|b| b.is_ascii_digit()) && !n.is_empty() => Some(format!(
            "-b is the FTP bounce host now, as in nmap, and {n:?} looks like a batch \
             size. Use `--batch-size {n}`."
        )),
        _ => None,
    }
}

/// Map `-oN`/`-oG`/`-oX`/`-oA` onto the long flag name, with any attached value.
fn output_flag(arg: &str) -> Option<(&'static str, String)> {
    for (short, long) in [
        ("-oN", "output-normal"),
        ("-oG", "output-grep"),
        ("-oX", "output-xml"),
        ("-oA", "output-all"),
    ] {
        if let Some(rest) = arg.strip_prefix(short) {
            return Some((long, rest.strip_prefix('=').unwrap_or(rest).to_string()));
        }
    }
    None
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
    // truemap's own words. nmap has no equivalent, but failing them as a u16 list
    // would be a confusing way to say "use --range".
    let is_word = |s: &str| matches!(s, "all" | "top1000" | "anchors");
    // Attached value: -p-, -p1-1000, -p-1024, --ports=1-
    if arg == "-p-" {
        return attached("-");
    }
    for pre in ["-p", "--ports="] {
        if let Some(rest) = arg.strip_prefix(pre) {
            if !rest.is_empty() && (rest.contains('-') || is_word(rest)) {
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
        if (n.contains('-') || is_word(n)) && !n.starts_with("--") {
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
        let b = parse(&["1.2.3.4", "--range", "20-25", "--exclude-ports", "22,23"]);
        assert_eq!(b.port_list().unwrap(), vec![20, 21, 24, 25]);
    }

    #[test]
    fn range_and_port_list_combine_and_dedupe() {
        let a = parse(&["1.2.3.4", "--range", "80-82", "-p", "81,443"]);
        assert_eq!(a.port_list().unwrap(), vec![80, 81, 82, 443]);
    }

    #[test]
    fn excluding_everything_is_an_error_not_an_empty_scan() {
        let a = parse(&["1.2.3.4", "-p", "80", "--exclude-ports", "80"]);
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
        // -g is NOT in this list any more: nmap owns that letter now.
        for f in ["-q", "--json", "--greppable", "--grep"] {
            let a = parse(&["1.2.3.4", f]);
            assert!(a.terse(), "{f} must be terse");
            assert!(!a.use_color(), "{f} must not colour");
        }
        assert!(!parse(&["1.2.3.4", "--accessible"]).use_color());
    }

    #[test]
    fn the_four_reassigned_letters_now_mean_what_nmap_means() {
        // The whole point of the change, and the reason it is breaking: these used
        // to be rustscan's. A rustscan command using them must FAIL, not silently
        // do something else.
        assert_eq!(parse(&["1.2.3.4", "-r"]).order(), ScanOrder::Serial);
        assert_eq!(parse(&["1.2.3.4", "-e", "eth0"]).interface.as_deref(), Some("eth0"));
        assert_eq!(parse(&["1.2.3.4", "-b", "ftp.example.com"]).ftp_bounce.as_deref(),
                   Some("ftp.example.com"));
        assert_eq!(parse(&["1.2.3.4", "-g", "53"]).source_port, Some(53));

        // ... and rustscan's meanings survive, long-only.
        assert_eq!(parse(&["1.2.3.4", "--range", "1-5"]).port_list().unwrap(),
                   vec![1, 2, 3, 4, 5]);
        assert_eq!(parse(&["1.2.3.4", "--batch-size", "10"]).batch_size, 10);
        assert!(parse(&["1.2.3.4", "--greppable"]).greppable);
        assert_eq!(parse(&["1.2.3.4", "--range", "20-25", "--exclude-ports", "22"])
                       .port_list().unwrap(), vec![20, 21, 23, 24, 25]);

        // A rustscan `-r 1-1000` must now be an ERROR rather than a scan of the
        // wrong thing. clap alone does NOT catch it -- `-r` is valueless, so
        // `1-1000` would become a positional TARGET and get resolved as a hostname.
        let errs = rw_errors(&["1.2.3.4", "-r", "1-1000"]);
        assert_eq!(errs.len(), 1, "the old spelling must be rejected, not guessed");
        assert!(errs[0].contains("takes no value"), "{}", errs[0]);
        assert!(errs[0].contains("--range 1-1000"), "must name the fix: {}", errs[0]);
        // And clap would indeed have swallowed it as a target, which is why the
        // check cannot be left to clap:
        let a = Args::parse_from(["truemap", "1.2.3.4", "-r", "1-1000"]);
        assert!(a.positional.contains(&"1-1000".to_string()),
                "proof that the rewrite check is load-bearing");
    }

    #[test]
    fn the_other_reassigned_letters_name_the_flag_you_meant() {
        for (args, needle) in [
            (vec!["1.2.3.4", "-e", "22,23"], "--exclude-ports 22,23"),
            (vec!["1.2.3.4", "-b", "4500"], "--batch-size 4500"),
            (vec!["1.2.3.4", "-r", "top1000"], "--range top1000"),
        ] {
            let e = rw_errors(&args);
            assert_eq!(e.len(), 1, "{args:?}");
            assert!(e[0].contains(needle), "{}", e[0]);
        }
        // A legitimate nmap-style use must NOT be flagged.
        assert!(rw_errors(&["-r", "10.0.0.1"]).is_empty(), "-r + a target is fine");
        assert!(rw_errors(&["-e", "eth0", "1.2.3.4"]).is_empty());
        assert!(rw_errors(&["-b", "ftp.example.com"]).is_empty());
    }

    #[test]
    fn the_unsupportable_flags_are_accepted_then_refused_with_a_reason() {
        // Accepted so the command parses, refused so it cannot be believed.
        for (args, needle) in [
            (vec!["1.2.3.4", "-e", "eth1"], "interface"),
            (vec!["1.2.3.4", "-b", "h:21"], "FTP bounce"),
            (vec!["1.2.3.4", "-g", "53"], "source port"),
        ] {
            let r = parse(&args).refusals();
            assert_eq!(r.len(), 1, "{args:?}");
            assert!(r[0].contains(needle), "{}", r[0]);
        }
        assert!(parse(&["1.2.3.4"]).refusals().is_empty(), "a plain scan refuses nothing");
    }

    #[test]
    fn nmap_output_flags_are_rewritten_and_accept_stdout() {
        for (short, field) in [("-oN", "output-normal"), ("-oG", "output-grep"),
                               ("-oX", "output-xml"), ("-oA", "output-all")] {
            assert_eq!(rw(&[short, "scan"]), vec![format!("--{field}=scan")], "{short}");
            assert_eq!(rw(&[&format!("{short}scan")]), vec![format!("--{field}=scan")]);
        }
        let a = Args::parse_from(std::iter::once("truemap".to_string()).chain(rw(&[
            "1.2.3.4", "-oN", "-", "-oX", "out.xml",
        ])));
        assert_eq!(a.output_normal.as_deref(), Some("-"));
        assert_eq!(a.output_xml.as_deref(), Some("out.xml"));
        assert!(a.stdout_is_a_report(), "the human view must not also go to stdout");
        assert!(a.terse(), "a report on stdout implies terse");
    }

    #[test]
    fn dash_p_n_is_accepted_as_a_no_op() {
        // truemap never pings, so -Pn is already the only behaviour. Accepting it
        // keeps a pasted nmap command working.
        assert_eq!(rw(&["-Pn"]), vec!["--pn"]);
        assert!(parse(&["1.2.3.4", "--pn"]).pn);
    }

    #[test]
    fn fast_and_top_ports_select_from_the_ranked_list() {
        assert_eq!(parse(&["1.2.3.4", "-F"]).port_list().unwrap().len(), 100);
        assert_eq!(parse(&["1.2.3.4", "--top-ports", "20"]).port_list().unwrap().len(), 20);
        // Asking for more than truemap ranks must say so rather than quietly
        // returning fewer ports than requested.
        let e = parse(&["1.2.3.4", "--top-ports", "5000"]).port_list().unwrap_err();
        assert!(e.contains("top 1000"), "{e}");
        assert!(parse(&["1.2.3.4", "--top-ports", "0"]).port_list().is_err());
    }

    #[test]
    fn the_word_port_specs_still_work_through_dash_p() {
        for w in ["all", "top1000", "anchors"] {
            let a = Args::parse_from(
                std::iter::once("truemap".to_string()).chain(rw(&["1.2.3.4", "-p", w])),
            );
            assert!(a.port_list().is_ok(), "-p {w} must not fail as a u16 list");
        }
        assert_eq!(
            Args::parse_from(std::iter::once("truemap".to_string())
                .chain(rw(&["1.2.3.4", "-p", "all"]))).port_list().unwrap().len(),
            65535
        );
    }

    #[test]
    fn nmaps_exclude_spelling_is_accepted() {
        assert_eq!(parse(&["-a", "10.0.0.1,10.0.0.2", "--exclude", "10.0.0.2"]).targets(),
                   vec!["10.0.0.1"]);
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
        let r = rewrite_nmap_flags(args.iter().map(|s| s.to_string()));
        assert!(r.errors.is_empty(), "unexpected rewrite errors: {:?}", r.errors);
        r.argv
    }

    fn rw_errors(args: &[&str]) -> Vec<String> {
        rewrite_nmap_flags(args.iter().map(|s| s.to_string())).errors
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
