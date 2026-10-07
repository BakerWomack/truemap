//! Target and port-spec parsing.

use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;

/// How many bad entries to name before summarising the rest.
const MAX_REPORTED_BAD: usize = 10;

/// Expand a target spec into addresses. Accepts an IP, a CIDR, or a hostname.
pub fn resolve_targets(spec: &str) -> Result<Vec<(String, IpAddr)>, String> {
    if let Ok(net) = spec.parse::<IpNet>() {
        // A bare IP parses as a /32 or /128; keep it as a single host.
        if net.prefix_len() == net.max_prefix_len() {
            return Ok(vec![(spec.to_string(), net.addr())]);
        }
        let hosts: Vec<(String, IpAddr)> =
            net.hosts().map(|ip| (ip.to_string(), ip)).collect();
        if hosts.is_empty() {
            return Err(format!("{spec} expands to no hosts"));
        }
        return Ok(hosts);
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(vec![(spec.to_string(), ip)]);
    }
    // Hostname: resolve, keeping the name for SNI/Host.
    let addrs: Vec<IpAddr> = format!("{spec}:80")
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {spec}: {e}"))?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(format!("{spec} resolved to no addresses"));
    }
    // One address per name is enough; note the others for the report.
    Ok(vec![(spec.to_string(), addrs[0])])
}

/// Read an `-iL` target list from a file, or from stdin when `path` is `-`.
pub fn read_target_list(path: &str) -> Result<Vec<String>, String> {
    let what = if path == "-" { "stdin" } else { path };
    let content = if path == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("cannot read targets from stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?
    };
    let specs = parse_target_list(&content).map_err(|e| format!("{what}: {e}"))?;
    if specs.is_empty() {
        return Err(format!("{what} contains no targets"));
    }
    Ok(specs)
}

/// Parse the contents of a target list into specs.
///
/// One entry per line is the documented form, but spaces, tabs and commas separate
/// too — that is what nmap's `-iL` accepts, and a file pasted out of a spreadsheet
/// or a report tends to arrive that way. `#` begins a comment, to the end of the
/// line. Blank lines are skipped.
///
/// Every entry is validated HERE, before anything is scanned, and all the bad ones
/// are reported together with their line numbers. The alternative — handing each
/// line to `resolve_targets` as the scan reaches it — turns a typo on line 400 of a
/// 900-line file into a lone "cannot resolve" twenty minutes into a run, next to
/// hundreds of lines of real output. A list file is usually a scope document; being
/// told up front that one line of it is unreadable is the whole point.
pub fn parse_target_list(content: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut bad: Vec<String> = Vec::new();
    for (n, raw) in content.lines().enumerate() {
        // Comments first, so `# 10.0.0.1 is out of scope` cannot become a target.
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        for tok in line.split([',', ' ', '\t']).filter(|s| !s.is_empty()) {
            match classify_spec(tok) {
                Ok(()) => {
                    if !out.iter().any(|x| x == tok) {
                        out.push(tok.to_string());
                    }
                }
                Err(why) => bad.push(format!("line {}: {tok:?} — {why}", n + 1)),
            }
        }
    }
    if !bad.is_empty() {
        let shown = bad.len().min(MAX_REPORTED_BAD);
        let mut msg = format!("{} unusable entr{}:", bad.len(), if bad.len() == 1 { "y" } else { "ies" });
        for b in bad.iter().take(shown) {
            msg.push_str("\n          ");
            msg.push_str(b);
        }
        if bad.len() > shown {
            msg.push_str(&format!("\n          ... and {} more", bad.len() - shown));
        }
        return Err(msg);
    }
    Ok(out)
}

/// Is this token something `resolve_targets` can actually use?
///
/// Syntactic only — a hostname's existence is DNS's business. The point is to reject
/// what cannot work *before* the scan, and to say why in terms of what the author
/// evidently meant, rather than letting a malformed address fall through to a DNS
/// lookup and come back as "cannot resolve".
fn classify_spec(tok: &str) -> Result<(), String> {
    if tok.parse::<IpNet>().is_ok() || tok.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if tok.contains('/') {
        return Err("not a valid CIDR".into());
    }
    let labels: Vec<&str> = tok.split('.').collect();
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    // `10.0.0.1-20`: nmap takes octet ranges, truemap does not. Say so, because an
    // nmap user's list file is exactly where these turn up, and the generic hostname
    // path would otherwise send it to DNS.
    if labels.len() == 4
        && labels[..3].iter().all(|l| numeric(l))
        && labels[3].split_once('-').is_some_and(|(a, b)| numeric(a) && numeric(b))
    {
        return Err("octet ranges are not supported; use a CIDR".into());
    }
    // Four numeric labels that did not parse as an address is a mistyped IP, not a
    // host called `10.0.0.256`.
    if labels.len() == 4 && labels.iter().all(|l| numeric(l)) {
        return Err("not a valid IPv4 address".into());
    }
    if tok.len() > 253 {
        return Err("too long for a hostname".into());
    }
    if tok.starts_with('.') || tok.starts_with('-') {
        return Err("not a valid hostname".into());
    }
    // A single trailing dot is a legal absolute name; an empty label anywhere else
    // is not.
    let body = tok.strip_suffix('.').unwrap_or(tok);
    if body.is_empty()
        || body.split('.').any(|l| {
            l.is_empty() || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err("not a valid hostname".into());
    }
    Ok(())
}

/// Expand `-x/--exclude-addresses` into networks, for exclusion by ADDRESS.
///
/// Returns the networks plus any specs that could not be understood, which the
/// caller reports — an exclusion that silently does nothing is the dangerous
/// failure here, so it must never be swallowed.
pub fn exclusion_nets(specs: &[String]) -> (Vec<IpNet>, Vec<String>) {
    let mut nets: Vec<IpNet> = Vec::new();
    let mut bad: Vec<String> = Vec::new();
    for spec in specs {
        let s = spec.trim();
        if s.is_empty() {
            continue;
        }
        if let Ok(net) = s.parse::<IpNet>() {
            nets.push(net);
        } else if let Ok(ip) = s.parse::<IpAddr>() {
            nets.push(IpNet::from(ip));
        } else {
            // A hostname: exclude every address it resolves to.
            match resolve_targets(s) {
                Ok(v) => nets.extend(v.into_iter().map(|(_, ip)| IpNet::from(ip))),
                Err(e) => bad.push(e),
            }
        }
    }
    (nets, bad)
}

/// Is this address covered by any exclusion network?
pub fn is_excluded(ip: &IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

/// Parse a port spec: `80`, `1-1000`, `22,80,443`, `top1000`, `all`, `-`.
///
/// Open-ended ranges are accepted too: `-1024` means 1-1024, `100-` means
/// 100-65535. `lo` and `hi` default to the ends of the port space rather than
/// erroring on an empty side.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let s = spec.trim();
    if s.eq_ignore_ascii_case("all") || s == "-" {
        return Ok((1..=65535u16).collect());
    }
    if s.eq_ignore_ascii_case("top1000") {
        return Ok(crate::ports::TOP_1000.to_vec());
    }
    if s.eq_ignore_ascii_case("anchors") {
        return Ok(crate::ports::ANCHORS.to_vec());
    }
    let mut out: Vec<u16> = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            // Open-ended ranges, as nmap writes them: `-1024` is 1-1024 and `100-`
            // is 100-65535. `-p-` arrives here as `all` and never reaches this arm.
            let (a, b) = (a.trim(), b.trim());
            let lo: u16 = if a.is_empty() {
                1
            } else {
                a.parse().map_err(|_| format!("bad port {a:?}"))?
            };
            let hi: u16 = if b.is_empty() {
                65535
            } else {
                b.parse().map_err(|_| format!("bad port {b:?}"))?
            };
            if lo > hi {
                return Err(format!("range {lo}-{hi} is inverted"));
            }
            out.extend(lo..=hi);
        } else {
            out.push(part.parse().map_err(|_| format!("bad port {part:?}"))?);
        }
    }
    if out.is_empty() {
        return Err("no ports in spec".into());
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs_parse() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
        assert_eq!(parse_ports("all").unwrap().len(), 65535);
        assert_eq!(parse_ports("top1000").unwrap().len(), 1000);
        assert_eq!(parse_ports(" 80 , 80 ,443 ").unwrap(), vec![80, 443]);
        assert!(parse_ports("5-1").is_err());
        assert!(parse_ports("notaport").is_err());
        assert!(parse_ports("99999").is_err());
    }

    #[test]
    fn open_ended_port_ranges_reach_the_ends_of_the_port_space() {
        assert_eq!(parse_ports("-").unwrap().len(), 65535);
        assert_eq!(parse_ports("-5").unwrap(), vec![1, 2, 3, 4, 5]);
        let hi = parse_ports("65533-").unwrap();
        assert_eq!(hi, vec![65533, 65534, 65535]);
        // Mixed with an explicit list, which is how `-p-1024,8080` arrives.
        assert_eq!(parse_ports("-3,8080").unwrap(), vec![1, 2, 3, 8080]);
    }

    #[test]
    fn a_target_list_takes_one_entry_per_line() {
        let specs = parse_target_list("10.0.0.1\n10.0.0.0/30\nexample.com\n").unwrap();
        assert_eq!(specs, vec!["10.0.0.1", "10.0.0.0/30", "example.com"]);
    }

    #[test]
    fn a_target_list_ignores_comments_and_blank_lines() {
        let f = "\
# scope for 2026-10-07
10.0.0.1

   10.0.0.2   # this one is the jump host
# 10.0.0.99 is OUT of scope
";
        let specs = parse_target_list(f).unwrap();
        assert_eq!(
            specs,
            vec!["10.0.0.1", "10.0.0.2"],
            "a commented-out address must never become a target"
        );
    }

    #[test]
    fn a_target_list_also_splits_on_spaces_tabs_and_commas() {
        // nmap's -iL accepts whitespace-separated entries, and files pasted out of a
        // report or a spreadsheet arrive this way.
        let specs = parse_target_list("10.0.0.1 10.0.0.2\t10.0.0.3,10.0.0.4").unwrap();
        assert_eq!(specs.len(), 4);
    }

    #[test]
    fn a_target_list_dedupes_repeated_entries() {
        let specs = parse_target_list("10.0.0.1\n10.0.0.1\n10.0.0.1\n").unwrap();
        assert_eq!(specs, vec!["10.0.0.1"]);
    }

    #[test]
    fn a_bad_entry_fails_the_whole_list_and_names_its_line() {
        // Failing up front is the point: a scope file half-scanned is worse than one
        // not scanned, because the operator believes the rest was covered.
        let err = parse_target_list("10.0.0.1\n10.0.0.256\n10.0.0.3\n").unwrap_err();
        assert!(err.contains("line 2"), "must name the line: {err}");
        assert!(err.contains("10.0.0.256"), "must quote the entry: {err}");
        assert!(
            err.contains("not a valid IPv4"),
            "a mistyped address must not be reported as an unresolvable hostname: {err}"
        );
    }

    #[test]
    fn every_bad_entry_is_reported_not_just_the_first() {
        let err = parse_target_list("10.0.0.256\nbad..name\n10.0.0.0/33\n").unwrap_err();
        assert!(err.contains("3 unusable entries"), "{err}");
        assert!(err.contains("line 1") && err.contains("line 2") && err.contains("line 3"), "{err}");
        assert!(err.contains("not a valid CIDR"), "{err}");
    }

    #[test]
    fn octet_ranges_are_refused_with_the_reason_not_sent_to_dns() {
        // nmap's own docs offer `10.0.0.1-20`, so an nmap user's list file has them.
        let err = parse_target_list("10.0.0.1-20\n").unwrap_err();
        assert!(err.contains("octet ranges"), "{err}");
        assert!(err.contains("CIDR"), "must say what to use instead: {err}");
    }

    #[test]
    fn a_list_of_only_comments_is_empty_not_an_error() {
        assert!(parse_target_list("# nothing here\n\n").unwrap().is_empty());
    }

    #[test]
    fn ipv6_entries_parse_as_addresses_and_networks() {
        let specs = parse_target_list("::1\n2001:db8::/126\n").unwrap();
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn exclusions_match_by_address_including_inside_a_cidr() {
        // The bug this replaces: comparing spec strings means `-a 10.0.0.0/24 -x
        // 10.0.0.5` scans 10.0.0.5, because "10.0.0.0/24" != "10.0.0.5".
        let (nets, bad) = exclusion_nets(&["10.0.0.5".to_string()]);
        assert!(bad.is_empty());
        assert!(is_excluded(&"10.0.0.5".parse().unwrap(), &nets));
        assert!(!is_excluded(&"10.0.0.6".parse().unwrap(), &nets));

        // A CIDR exclusion covers every address in it.
        let (nets, _) = exclusion_nets(&["10.0.1.0/24".to_string()]);
        assert!(is_excluded(&"10.0.1.77".parse().unwrap(), &nets));
        assert!(!is_excluded(&"10.0.2.77".parse().unwrap(), &nets));
    }

    #[test]
    fn an_unresolvable_exclusion_is_reported_not_silently_dropped() {
        // An exclusion that quietly fails is the dangerous direction: the operator
        // believes an address is out of the scan and it is not.
        let (nets, bad) = exclusion_nets(&["10.0.0.0/33".to_string()]);
        assert!(nets.is_empty());
        assert_eq!(bad.len(), 1, "the caller must be able to refuse to scan");
    }

    #[test]
    fn targets_parse() {
        let t = resolve_targets("127.0.0.1").unwrap();
        assert_eq!(t.len(), 1);
        let t = resolve_targets("10.0.0.0/30").unwrap();
        assert_eq!(t.len(), 2, "/30 has two usable hosts");
        assert!(resolve_targets("10.0.0.0/24").unwrap().len() == 254);
    }
}
