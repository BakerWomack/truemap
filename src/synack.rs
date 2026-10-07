//! The TCP-layer discriminator: read the SYN-ACK itself. Needs CAP_NET_RAW.
//!
//! Implements the SYN/ACK test from *Uncovering Network Tarpits with Degreaser*
//! (Alt, Beverly, Dainotti — ACSAC 2014), whose two measured discriminators are:
//!
//!   * **Receive window < 20.** In the authors' backbone traces ~99.7% of real TCP
//!     connections used a window > 512, and none used the characteristic tarpit
//!     windows. LaBrea advertises 10; the netfilter TARPIT target advertises 5;
//!     zero-window responders advertise 0.
//!   * **No TCP options.** LaBrea and the netfilter plugin forge packets without
//!     the host stack, so they negotiate no options at all. Under 0.5% of real
//!     connections carry no options. MSS is excluded from this test because
//!     middleboxes are known to inject it.
//!
//! The honest limit, which the paper states and which matters more in 2026 than it
//! did in 2014: a **SYN-cookie proxy terminates TCP with a real stack**, so it
//! emits a normal window and a full option set on every port. Against F5
//! SYNcookie, Fortinet, SonicWall or AWS Global Accelerator this layer correctly
//! says "these look real" and is simply blind. That is why `discriminate` refuses
//! to return a verdict when nearly everything passes, and why the application
//! layer — not this module — is the primary engine.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};

/// Degreaser's measured threshold: a receive window below this is a tarpit shape.
pub const WINDOW_TARPIT_MAX: u16 = 20;
/// If more than this many ports look "real" at layer 4, the signal cannot
/// discriminate on this host (a SYN-cookie proxy) — return nothing rather than
/// bless a fabricated mass.
pub const MAX_REAL: usize = 64;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SynAck {
    pub port: u16,
    pub window: u16,
    pub has_mss: bool,
    /// Any option other than MSS/NOP/EOL — middleboxes inject MSS, so it is excluded.
    pub has_other_opts: bool,
    pub ttl: u8,
}

impl SynAck {
    /// Does this SYN-ACK look like it came from a real TCP stack?
    pub fn looks_real(&self) -> bool {
        self.window >= WINDOW_TARPIT_MAX || self.has_other_opts
    }

    /// Narrow the tarpit family from the window value.
    ///
    /// Deliberately hedged. The window pins the *shape*, not the product: LaBrea
    /// defaults to 10 and netfilter TARPIT to 5, but LaBrea's window is
    /// configurable and netfilter DELUDE shares the shape. Telling those apart
    /// needs degreaser's follow-up packets (ACK -> RST means DELUDE; ACK -> window
    /// 0 means TARPIT; a zero-window probe separates persistent LaBrea from
    /// non-persistent), which this module does not send. The application layer
    /// catches the difference anyway: DELUDE resets the connection, a tarpit
    /// freezes it.
    pub fn family(&self) -> &'static str {
        match self.window {
            0 => "zero-window tarpit shape (netfilter TARPIT/DELUDE family)",
            5 => "tiny-window tarpit shape, window 5 (netfilter xtables TARPIT default)",
            10 => "tiny-window tarpit shape, window 10 (LaBrea default; DELUDE shares it)",
            w if w < WINDOW_TARPIT_MAX => "tiny-window tarpit shape (unrecognised window)",
            _ => "real stack",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct L4Verdict {
    pub probed: usize,
    pub answered: usize,
    pub real: Vec<u16>,
    pub tarpit: Vec<u16>,
    pub note: String,
    /// False when the discriminator is blind here (SYN-cookie proxy).
    pub usable: bool,
}

/// Decide from a set of SYN-ACKs. Pure; unit-tested without a network.
pub fn discriminate(acks: &[SynAck], probed: usize, max_real: usize) -> L4Verdict {
    let real: Vec<u16> = acks.iter().filter(|a| a.looks_real()).map(|a| a.port).collect();
    let tarpit: Vec<u16> = acks.iter().filter(|a| !a.looks_real()).map(|a| a.port).collect();

    if acks.is_empty() {
        return L4Verdict {
            probed, answered: 0, real: vec![], tarpit: vec![],
            note: "no SYN-ACK received — nothing to fingerprint at layer 4".into(),
            usable: false,
        };
    }
    if real.len() > max_real {
        return L4Verdict {
            probed,
            answered: acks.len(),
            real: vec![],
            tarpit: vec![],
            note: format!(
                "{} ports returned a normal window and full TCP options — consistent with a \
                 SYN-cookie proxy that terminates TCP with a real stack. The layer-4 \
                 discriminator is blind here and returns nothing; the application layer decides.",
                real.len()
            ),
            usable: false,
        };
    }
    let fam = tarpit
        .first()
        .and_then(|p| acks.iter().find(|a| a.port == *p))
        .map(|a| a.family())
        .unwrap_or("real stack");
    L4Verdict {
        probed,
        answered: acks.len(),
        note: format!(
            "{} of {} SYN-ACKs carried a tarpit shape (window < {WINDOW_TARPIT_MAX} and no TCP \
             options beyond MSS): {fam}. {} carried a real TCP stack's fingerprint.",
            tarpit.len(),
            acks.len(),
            real.len()
        ),
        real,
        tarpit,
        usable: true,
    }
}

pub fn available() -> bool {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).is_ok()
}

pub fn unavailable_reason() -> String {
    "raw sockets unavailable — the TCP-layer (window/options) tarpit test needs CAP_NET_RAW. \
     Run with sudo, or grant it once: sudo setcap cap_net_raw+ep $(which truemap). \
     Without it only the application-layer engine runs, which is the primary engine anyway."
        .to_string()
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a TCP SYN carrying the common option set (MSS, SACK-permitted, timestamps,
/// window scale), as degreaser does — so that a *missing* option set in the reply is
/// meaningful rather than a consequence of our own stripped-down probe.
pub fn build_syn(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) -> Vec<u8> {
    let opts: Vec<u8> = vec![
        0x02, 0x04, 0x05, 0xb4, // MSS 1460
        0x04, 0x02, // SACK permitted
        0x08, 0x0a, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, // timestamps
        0x01, // NOP
        0x03, 0x03, 0x07, // window scale 7
    ];
    let data_off = (20 + opts.len()) / 4;
    let mut tcp = Vec::with_capacity(20 + opts.len());
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(((data_off as u8) << 4) | 0);
    tcp.push(0x02); // SYN
    tcp.extend_from_slice(&64240u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
    tcp.extend_from_slice(&opts);

    // TCP checksum over the IPv4 pseudo-header + segment.
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6); // IPPROTO_TCP
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    let ck = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&ck.to_be_bytes());
    tcp
}

/// Parse a raw IPv4 packet; return the SYN-ACK fingerprint if it answers `our_sport`.
pub fn parse_reply(pkt: &[u8], our_sport: u16) -> Option<SynAck> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let ttl = pkt[8];
    if pkt.len() < ihl + 20 {
        return None;
    }
    let tcp = &pkt[ihl..];
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dport != our_sport {
        return None;
    }
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];
    if flags & 0x12 != 0x12 {
        return None; // need SYN+ACK
    }
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    let opts: &[u8] = if data_off > 20 && tcp.len() >= data_off {
        &tcp[20..data_off]
    } else {
        &[]
    };
    let (has_mss, has_other) = scan_options(opts);
    Some(SynAck { port: sport, window, has_mss, has_other_opts: has_other, ttl })
}

/// Walk the TCP option list. Returns (has_mss, has_any_option_other_than_mss).
pub fn scan_options(opts: &[u8]) -> (bool, bool) {
    let mut i = 0;
    let mut has_mss = false;
    let mut has_other = false;
    while i < opts.len() {
        match opts[i] {
            0 => break,     // EOL
            1 => { i += 1; continue } // NOP: padding, not a negotiated option
            kind => {
                if i + 1 >= opts.len() {
                    break;
                }
                let len = opts[i + 1] as usize;
                if len < 2 {
                    break;
                }
                if kind == 2 {
                    has_mss = true;
                } else {
                    has_other = true;
                }
                i += len;
            }
        }
    }
    (has_mss, has_other)
}

fn local_ip_toward(dst: Ipv4Addr) -> Ipv4Addr {
    let s = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Ipv4Addr::UNSPECIFIED,
    };
    if s.connect(SocketAddr::new(IpAddr::V4(dst), 80)).is_err() {
        return Ipv4Addr::UNSPECIFIED;
    }
    match s.local_addr() {
        Ok(SocketAddr::V4(a)) => *a.ip(),
        _ => Ipv4Addr::UNSPECIFIED,
    }
}

/// Blocking raw SYN scan. Returns the SYN-ACKs we could read.
pub fn syn_scan(dst: Ipv4Addr, ports: &[u16], wait: Duration) -> std::io::Result<Vec<SynAck>> {
    use std::mem::MaybeUninit;

    let send = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    let recv = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    // A tarpit answers every SYN, so a wide probe set means a burst of replies.
    // Undercounting them would look like "no real service found".
    let _ = recv.set_recv_buffer_size(4 << 20);
    recv.set_nonblocking(true)?;

    let src = local_ip_toward(dst);
    // Outside the ephemeral range, so the kernel is less likely to own the reply.
    let sport: u16 = 61000 + (std::process::id() as u16 % 1000);
    let seq: u32 = 0x1234_5678;

    for &p in ports {
        let pkt = build_syn(src, dst, sport, p, seq);
        let to = SocketAddr::new(IpAddr::V4(dst), 0);
        let _ = send.send_to(&pkt, &to.into());
    }

    let mut out: Vec<SynAck> = Vec::new();
    let deadline = Instant::now() + wait;
    let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
    while Instant::now() < deadline && out.len() < ports.len() {
        match recv.recv_from(&mut buf) {
            Ok((n, from)) => {
                let bytes: Vec<u8> =
                    buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
                let ok_src = from
                    .as_socket_ipv4()
                    .map(|a| *a.ip() == dst)
                    .unwrap_or(false);
                if !ok_src {
                    continue;
                }
                if let Some(sa) = parse_reply(&bytes, sport) {
                    if ports.contains(&sa.port) && !out.iter().any(|x| x.port == sa.port) {
                        out.push(sa);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(port: u16, window: u16, has_mss: bool, has_other: bool) -> SynAck {
        SynAck { port, window, has_mss, has_other_opts: has_other, ttl: 64 }
    }

    #[test]
    fn degreaser_thresholds_match_the_paper() {
        // LaBrea: window 10, no options -> tarpit.
        assert!(!ack(80, 10, false, false).looks_real());
        assert!(ack(80, 10, false, false).family().contains("window 10"));
        // netfilter TARPIT: window 5.
        assert!(!ack(80, 5, false, false).looks_real());
        assert!(ack(80, 5, false, false).family().contains("window 5"));
        // The window pins the shape, not the product -- it must not claim one.
        assert!(!ack(80, 10, false, false).family().starts_with("LaBrea"));
        // Zero window.
        assert!(!ack(80, 0, false, false).looks_real());
        // A real stack: large window.
        assert!(ack(80, 64240, true, true).looks_real());
        // The paper's exact boundary: < 20 is tarpit, >= 20 is not.
        assert!(!ack(80, 19, false, false).looks_real());
        assert!(ack(80, 20, false, false).looks_real());
    }

    #[test]
    fn a_tiny_window_with_real_options_is_not_called_a_tarpit() {
        // Options are negotiated by a real stack; a genuinely congested host with a
        // small window must not be mislabelled.
        assert!(ack(80, 4, false, true).looks_real());
    }

    #[test]
    fn mss_alone_does_not_count_as_options_because_middleboxes_inject_it() {
        let (mss, other) = scan_options(&[0x02, 0x04, 0x05, 0xb4]);
        assert!(mss && !other);
        // NOPs are padding, not negotiation.
        let (_, other) = scan_options(&[0x01, 0x01, 0x02, 0x04, 0x05, 0xb4]);
        assert!(!other);
        // SACK-permitted is a real negotiated option.
        let (_, other) = scan_options(&[0x04, 0x02]);
        assert!(other);
        // Malformed length must not loop forever.
        let (_, _) = scan_options(&[0x08, 0x00, 0xff]);
    }

    #[test]
    fn a_syn_cookie_proxy_makes_the_l4_signal_refuse_to_answer() {
        // 500 ports all with a real-looking stack: that is a proxy, not 500 services.
        let acks: Vec<SynAck> = (1..=500u16).map(|p| ack(p, 64240, true, true)).collect();
        let v = discriminate(&acks, 500, MAX_REAL);
        assert!(!v.usable, "must refuse rather than bless 500 fake 'real' ports");
        assert!(v.real.is_empty());
        assert!(v.note.contains("SYN-cookie proxy"));
    }

    #[test]
    fn a_tarpit_with_two_real_services_is_resolved() {
        let mut acks: Vec<SynAck> = (1..=300u16).map(|p| ack(p, 10, false, false)).collect();
        acks.push(ack(22, 64240, true, true));
        acks.push(ack(443, 65535, true, true));
        let v = discriminate(&acks, 302, MAX_REAL);
        assert!(v.usable);
        assert_eq!(v.real, vec![22, 443]);
        assert_eq!(v.tarpit.len(), 300);
    }

    #[test]
    fn syn_packet_is_well_formed_with_a_valid_checksum() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let pkt = build_syn(src, dst, 61000, 80, 0x1234_5678);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 61000);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 80);
        assert_eq!(pkt[13], 0x02, "SYN flag only");
        let data_off = ((pkt[12] >> 4) as usize) * 4;
        assert_eq!(data_off, pkt.len(), "data offset must cover the options");
        // The options we claim to send must actually be there.
        let (mss, other) = scan_options(&pkt[20..]);
        assert!(mss && other, "our SYN must carry a full option set");
        // Verify the checksum by recomputing over the pseudo-header: it must be 0.
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&pkt);
        assert_eq!(checksum(&pseudo), 0, "TCP checksum must validate");
    }

    #[test]
    fn parse_reply_extracts_window_and_options_and_rejects_foreign_packets() {
        // Hand-build an IPv4 + SYN-ACK with window 10 and no options.
        let mut pkt = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 51 /*ttl*/, 6, 0, 0,
                           10, 0, 0, 2, 10, 0, 0, 1];
        pkt.extend_from_slice(&80u16.to_be_bytes()); // sport
        pkt.extend_from_slice(&61000u16.to_be_bytes()); // dport
        pkt.extend_from_slice(&[0; 8]); // seq, ack
        pkt.push(5 << 4); // data offset 20
        pkt.push(0x12); // SYN+ACK
        pkt.extend_from_slice(&10u16.to_be_bytes()); // window 10
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        let sa = parse_reply(&pkt, 61000).expect("should parse");
        assert_eq!(sa.port, 80);
        assert_eq!(sa.window, 10);
        assert_eq!(sa.ttl, 51);
        assert!(!sa.looks_real());
        // Wrong source port -> not ours.
        assert!(parse_reply(&pkt, 62000).is_none());
        // A RST+ACK is not a SYN-ACK.
        let mut rst = pkt.clone();
        rst[33] = 0x14;
        assert!(parse_reply(&rst, 61000).is_none());
        // Truncated input must not panic.
        assert!(parse_reply(&pkt[..10], 61000).is_none());
    }
}
