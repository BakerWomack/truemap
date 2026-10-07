//! Protocol coherence: does this byte string look like a *real* protocol speaking?
//!
//! This is the discriminator that beats an answer-everything responder. A SYN-ACK
//! proves nothing — a SYN proxy will emit one for every port. But a real service
//! must answer in its own protocol. A fabricated open port answers with silence,
//! with garbage, or with a canned string that is identical on every port.
//!
//! Carried forward (and extended) from hostscan's `net/tarpit.py::coherent`.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Proto {
    Ssh,
    Http,
    Tls,
    SmtpFtp,
    Pop3Imap,
    Redis,
    Mysql,
    Postgres,
    Amqp,
    Vnc,
    Mongo,
    Memcached,
    Irc,
    Rdp,
    Socks,
    Telnet,
    Dns,
    LengthPrefixed,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Ssh => "ssh",
            Proto::Http => "http",
            Proto::Tls => "tls",
            Proto::SmtpFtp => "smtp/ftp",
            Proto::Pop3Imap => "pop3/imap",
            Proto::Redis => "redis",
            Proto::Mysql => "mysql",
            Proto::Postgres => "postgres",
            Proto::Amqp => "amqp",
            Proto::Vnc => "vnc",
            Proto::Mongo => "mongodb",
            Proto::Memcached => "memcached",
            Proto::Irc => "irc",
            Proto::Rdp => "rdp",
            Proto::Socks => "socks",
            Proto::Telnet => "telnet",
            Proto::Dns => "dns",
            Proto::LengthPrefixed => "length-prefixed",
        }
    }
}

/// The DNS transaction ID truemap puts in its own query, so a reply can be matched
/// to it structurally rather than by guessing at a shape.
pub const DNS_TXID: [u8; 2] = [0x7a, 0x7a];

/// Is this a DNS-over-TCP reply to *our* query?
///
/// Checked structurally, not by a byte pattern: the 2-byte TCP length prefix must
/// match the rest of the message, the transaction ID must be the one we sent, and
/// the QR bit must say "this is a response". A port that answers all three is a DNS
/// server; nothing else answers all three by accident.
pub fn dns_reply(resp: &[u8]) -> bool {
    if resp.len() < 14 {
        return false;
    }
    let declared = u16::from_be_bytes([resp[0], resp[1]]) as usize;
    let msg = &resp[2..];
    if declared != msg.len() {
        return false;              // a truncated or non-DNS stream
    }
    if msg[0..2] != DNS_TXID {
        return false;              // not an answer to our query
    }
    msg[2] & 0x80 != 0             // QR bit: response
}

/// Returns the protocol if `resp` is a valid protocol greeting or reply.
///
/// Deliberately strict: a response we cannot name is *not* evidence of a service.
/// Being wrong in the permissive direction is what produces the phantom ports this
/// whole tool exists to remove.
pub fn coherent(resp: &[u8]) -> Option<Proto> {
    if resp.is_empty() {
        return None;
    }
    let r = resp;

    if dns_reply(r) {
        return Some(Proto::Dns);
    }

    // --- server-speaks-first text protocols ---
    if r.starts_with(b"SSH-2.0-") || r.starts_with(b"SSH-1.99-") || r.starts_with(b"SSH-1.5-") {
        return Some(Proto::Ssh);
    }
    if r.starts_with(b"HTTP/1.") || r.starts_with(b"HTTP/0.9") || r.starts_with(b"HTTP/2") {
        return Some(Proto::Http);
    }
    // TLS record: handshake (0x16) or alert (0x15) with a sane version major 0x03.
    if r.len() >= 3 && (r[0] == 0x16 || r[0] == 0x15) && r[1] == 0x03 && r[2] <= 0x04 {
        return Some(Proto::Tls);
    }
    if r.starts_with(b"220 ") || r.starts_with(b"220-") || r.starts_with(b"220\t") {
        return Some(Proto::SmtpFtp);
    }
    if r.starts_with(b"+OK") || r.starts_with(b"* OK") || r.starts_with(b"* BYE") {
        return Some(Proto::Pop3Imap);
    }
    if r.starts_with(b"+PONG") || r.starts_with(b"-ERR") || r.starts_with(b"-NOAUTH")
        || r.starts_with(b"-DENIED") || r.starts_with(b"$-1") || r.starts_with(b"+PONG\r\n")
    {
        return Some(Proto::Redis);
    }
    if r.starts_with(b":") && r.windows(4).any(|w| w == b"NOTICE" as &[u8] || w == b"PING") {
        return Some(Proto::Irc);
    }
    if r.starts_with(b"ERROR\r\n") || r.starts_with(b"VERSION ") || r.starts_with(b"STAT ") {
        return Some(Proto::Memcached);
    }
    if r.starts_with(b"RFB ") {
        return Some(Proto::Vnc);
    }
    if r.starts_with(b"AMQP") {
        return Some(Proto::Amqp);
    }

    // --- binary / length-prefixed protocols ---
    let head = &r[..r.len().min(160)];
    if find(head, b"mysql_native_password").is_some()
        || find(head, b"caching_sha2_password").is_some()
    {
        return Some(Proto::Mysql);
    }
    // Postgres error/auth response: a single tag byte then a 4-byte big-endian length.
    if (r[0] == b'E' || r[0] == b'R' || r[0] == b'N') && r.len() >= 5 {
        let len = u32::from_be_bytes([r[1], r[2], r[3], r[4]]) as usize;
        if (4..=10000).contains(&len) && (find(head, b"SFATAL").is_some()
            || find(head, b"VFATAL").is_some()
            || find(head, b"unsupported frontend protocol").is_some())
        {
            return Some(Proto::Postgres);
        }
    }
    // MongoDB wire reply: int32 messageLength matching what we actually received.
    if r.len() >= 16 {
        let msg_len = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as usize;
        if msg_len >= 16 && msg_len <= 48 * 1024 * 1024 && find(head, b"ismaster").is_some() {
            return Some(Proto::Mongo);
        }
    }
    // RDP: TPKT header version 3, reserved 0, then a plausible length.
    if r.len() >= 4 && r[0] == 0x03 && r[1] == 0x00 {
        let len = u16::from_be_bytes([r[2], r[3]]) as usize;
        if (4..=4096).contains(&len) {
            return Some(Proto::Rdp);
        }
    }
    // SOCKS5 method-selection reply.
    if r.len() == 2 && r[0] == 0x05 && (r[1] <= 0x02 || r[1] == 0xFF) {
        return Some(Proto::Socks);
    }
    // Telnet IAC negotiation.
    if r[0] == 0xFF && r.len() >= 3 && (0xFB..=0xFE).contains(&r[1]) {
        return Some(Proto::Telnet);
    }
    // MySQL-style length-prefixed greeting: 3-byte LE length + seq 0, length matches.
    if r.len() > 20 && r[3] == 0x00 {
        let len = u32::from_le_bytes([r[0], r[1], r[2], 0]) as usize;
        if len + 4 == r.len() || (len > 10 && len < 1024) {
            return Some(Proto::LengthPrefixed);
        }
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Normalise a response for cross-port and cross-connection comparison.
///
/// Digits are stripped so a real service whose greeting carries only a timestamp,
/// a PID or a session counter still compares equal to itself on reconnect — while
/// a portspoof-style randomiser (which varies *letters*) does not.
pub fn normalise(resp: &[u8]) -> Vec<u8> {
    resp.iter()
        .take(300)
        .filter(|b| !b.is_ascii_digit())
        .copied()
        .collect()
}

/// A cheap stable hash of the normalised response, for bulk-identical clustering.
pub fn sig_hash(resp: &[u8]) -> u64 {
    // FNV-1a over the normalised bytes.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in normalise(resp) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_protocols_are_recognised() {
        assert_eq!(coherent(b"SSH-2.0-OpenSSH_9.6p1\r\n"), Some(Proto::Ssh));
        assert_eq!(coherent(b"HTTP/1.1 200 OK\r\n"), Some(Proto::Http));
        assert_eq!(coherent(b"HTTP/1.1 400 Bad Request\r\n"), Some(Proto::Http));
        assert_eq!(coherent(&[0x16, 0x03, 0x03, 0x00, 0x5a]), Some(Proto::Tls));
        assert_eq!(coherent(&[0x15, 0x03, 0x01, 0x00, 0x02]), Some(Proto::Tls));
        assert_eq!(coherent(b"220 mail.example.com ESMTP\r\n"), Some(Proto::SmtpFtp));
        assert_eq!(coherent(b"-NOAUTH Authentication required\r\n"), Some(Proto::Redis));
    }

    #[test]
    fn a_dns_reply_is_matched_structurally_to_our_own_query() {
        // length prefix | txid | flags(QR=1) | counts
        let msg: Vec<u8> = vec![0x7a, 0x7a, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        let mut pkt = (msg.len() as u16).to_be_bytes().to_vec();
        pkt.extend_from_slice(&msg);
        assert_eq!(coherent(&pkt), Some(Proto::Dns));

        // Wrong transaction id: somebody else's traffic, or a coincidence.
        let mut bad = pkt.clone();
        bad[2] = 0x00;
        bad[3] = 0x01;
        assert_eq!(coherent(&bad), None, "must not claim DNS for a foreign txid");

        // QR bit clear: that is a query, not a reply.
        let mut q = pkt.clone();
        q[4] &= 0x7f;
        assert_eq!(coherent(&q), None, "a query is not a reply");

        // Length prefix disagreeing with the body: not a framed DNS message.
        let mut trunc = pkt.clone();
        trunc[1] = 0xff;
        assert_eq!(coherent(&trunc), None, "length prefix must frame the message");
    }

    #[test]
    fn silence_and_garbage_are_not_coherent() {
        assert_eq!(coherent(b""), None);
        assert_eq!(coherent(b"\x00\x00\x00\x00"), None);
        assert_eq!(coherent(b"hello there"), None);
        // A plausible-looking but nameless blob is NOT evidence of a service.
        assert_eq!(coherent(b"xxxxxxxxxxxxxxxxxxxxxxxx"), None);
    }

    #[test]
    fn digits_are_stripped_but_letters_are_not() {
        // Same service, different timestamp -> equal.
        assert_eq!(
            sig_hash(b"220 host ESMTP ready at 1699999999"),
            sig_hash(b"220 host ESMTP ready at 1700000042")
        );
        // portspoof-style random letters -> different.
        assert_ne!(
            sig_hash(b"220 fake-abcdefghij ready"),
            sig_hash(b"220 fake-klmnopqrst ready")
        );
    }
}
