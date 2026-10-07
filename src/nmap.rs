//! The nmap hand-off, as rustscan does it — with one difference that is the point.
//!
//! rustscan passes nmap every port that returned a SYN-ACK. On a host behind a SYN
//! proxy that is all 65535, so nmap spends its whole run doing version detection
//! against ports with nothing behind them and reports them `tcpwrapped`.
//!
//! truemap passes nmap only the ports it **proved** at the application layer. Same
//! command, same output format, but against a SYN-proxied host that is the
//! difference between handing nmap 2 ports and handing it 65535.

use std::process::Command;

/// Build the argument list for nmap. Pure, so the composition is unit-testable
/// without running anything.
///
/// `-Pn` is forced because truemap has already established reachability far more
/// cheaply than an nmap ping sweep would, and `-p` is forced to the proven set so a
/// user's own `-p` cannot silently reintroduce the phantom ports.
pub fn build_args(user: &[String], ports: &[u16], target: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut skip_next = false;
    for a in user {
        if skip_next {
            skip_next = false;
            continue;
        }
        // Drop a user -p/--ports: truemap decides the port set here, and silently
        // honouring theirs would undo the whole proving step.
        if a == "-p" || a == "--ports" {
            skip_next = true;
            continue;
        }
        if a.starts_with("-p") && a.len() > 2 && a[2..].chars().next().unwrap().is_ascii_digit() {
            continue;
        }
        if a == "-Pn" {
            continue; // added below; avoid passing it twice
        }
        out.push(a.clone());
    }
    out.push("-Pn".into());
    out.push("-p".into());
    out.push(
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push(target.to_string());
    out
}

/// Run nmap against the proven ports, streaming its output straight through.
pub fn run(user: &[String], ports: &[u16], target: &str) -> Result<i32, String> {
    if ports.is_empty() {
        return Err("no proven ports — nothing to hand to nmap".into());
    }
    let args = build_args(user, ports, target);
    eprintln!("truemap: nmap {}", args.join(" "));
    match Command::new("nmap").args(&args).status() {
        Ok(st) => Ok(st.code().unwrap_or(-1)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("nmap is not installed or not on PATH".into())
        }
        Err(e) => Err(format!("could not run nmap: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_proven_ports_are_what_nmap_gets() {
        let a = build_args(&v(&["-A", "-sC"]), &[22, 443], "10.0.0.1");
        assert_eq!(a, v(&["-A", "-sC", "-Pn", "-p", "22,443", "10.0.0.1"]));
    }

    #[test]
    fn a_user_port_flag_cannot_reintroduce_the_phantom_ports() {
        // The whole point is that nmap sees the proven set. Honouring a user -p
        // here would hand back the 65535 ports truemap just finished rejecting.
        for form in [v(&["-p", "1-65535"]), v(&["--ports", "1-65535"]), v(&["-p1-65535"])] {
            let a = build_args(&form, &[22], "h");
            let joined = a.join(" ");
            assert!(!joined.contains("65535"), "user port spec must be dropped: {joined}");
            assert_eq!(a.iter().filter(|x| *x == "-p").count(), 1, "exactly one -p");
        }
    }

    #[test]
    fn pn_is_forced_but_never_duplicated() {
        let a = build_args(&v(&["-Pn", "-sV"]), &[80], "h");
        assert_eq!(a.iter().filter(|x| *x == "-Pn").count(), 1);
        assert!(a.contains(&"-sV".to_string()));
    }

    #[test]
    fn a_script_arg_that_merely_starts_with_p_survives() {
        // `-pn` is not a port spec and neither is `--privileged`; only a -p followed
        // by a digit, or an exact -p/--ports, is dropped.
        let a = build_args(&v(&["--privileged", "-sS"]), &[80], "h");
        assert!(a.contains(&"--privileged".to_string()));
        assert!(a.contains(&"-sS".to_string()));
    }

    #[test]
    fn the_target_is_last_as_nmap_expects() {
        let a = build_args(&v(&["-A"]), &[80], "example.com");
        assert_eq!(a.last().unwrap(), "example.com");
    }

    #[test]
    fn no_proven_ports_is_an_error_not_an_nmap_run_over_everything() {
        assert!(run(&v(&["-A"]), &[], "h").is_err());
    }
}
