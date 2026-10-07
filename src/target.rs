//! Target and port-spec parsing.

use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;

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

/// Parse a port spec: `80`, `1-1000`, `22,80,443`, `top1000`, `all`.
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
            let lo: u16 = a.trim().parse().map_err(|_| format!("bad port {a:?}"))?;
            let hi: u16 = b.trim().parse().map_err(|_| format!("bad port {b:?}"))?;
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
    fn targets_parse() {
        let t = resolve_targets("127.0.0.1").unwrap();
        assert_eq!(t.len(), 1);
        let t = resolve_targets("10.0.0.0/30").unwrap();
        assert_eq!(t.len(), 2, "/30 has two usable hosts");
        assert!(resolve_targets("10.0.0.0/24").unwrap().len() == 254);
    }
}
