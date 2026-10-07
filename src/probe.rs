//! The application-layer probe ladder, and the per-port behavioural signature.
//!
//! A TCP handshake is not evidence. This module goes one step further on every
//! candidate port and records *how the port behaved* — which is the thing we can
//! compare against a known-closed control port on the same host.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::coherent::{coherent, sig_hash, Proto, DNS_TXID};

/// How the TCP connect itself ended. The distinction `connected`-or-not threw
/// away is the one that answers "is this host alive": a RST is the host actively
/// declining, which proves it is there; a timeout proves nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Dial {
    /// Handshake completed.
    Connected,
    /// Actively refused — a RST, or an immediate error. The host answered.
    Refused,
    /// Nothing came back. Dropped, filtered, or dead; this cannot tell which.
    TimedOut,
}

/// Which probe, if any, got the port to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Spoke {
    /// The service greeted us first (ssh, smtp, mysql...).
    Greeting,
    /// It answered a plaintext HTTP request.
    HttpProbe,
    /// It answered a TLS ClientHello.
    TlsProbe,
    /// It said nothing to anything we sent.
    Nothing,
}

/// How the connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Close {
    /// Clean EOF with no data ever sent — the `tcpwrapped` shape.
    EofNoData,
    /// EOF after it sent us data.
    EofAfterData,
    /// Reset.
    Reset,
    /// Still open when we gave up: accepted and held. The tarpit shape.
    HeldOpen,
}

/// Everything we observed about one port, in a form that can be compared to the
/// signature of a port we *know* is closed.
#[derive(Debug, Clone, Serialize)]
pub struct Signature {
    pub connected: bool,
    /// How the connect ended. `connected` only says "not Connected"; this says why.
    pub dial: Dial,
    pub connect_ms: u64,
    pub bytes: usize,
    /// Digit-stripped hash of the response, for cross-port identity comparison.
    pub hash: u64,
    pub proto: Option<Proto>,
    pub spoke: Spoke,
    pub close: Close,
    /// First 120 bytes, lossily printable — for the report, not for comparison.
    pub sample: String,
}

impl Signature {
    pub fn unreachable(dial: Dial) -> Self {
        Signature {
            connected: false,
            dial,
            connect_ms: 0,
            bytes: 0,
            hash: 0,
            proto: None,
            spoke: Spoke::Nothing,
            close: Close::Reset,
            sample: String::new(),
        }
    }

    /// The comparable part of the signature: behaviour, not timing.
    ///
    /// Timing is deliberately excluded. Degreaser (ACSAC 2014) makes the same
    /// choice — a classifier that depends on response time is a classifier that
    /// changes its answer when the network is busy.
    pub fn shape(&self) -> (bool, u64, Option<Proto>, Spoke, Close) {
        (self.connected, self.hash, self.proto, self.spoke, self.close)
    }

    /// True if this port behaved indistinguishably from the given control port.
    pub fn matches(&self, control: &Signature) -> bool {
        self.shape() == control.shape()
    }
}

/// Keep reading until the peer stops talking, so the signature is deterministic.
///
/// A single `read()` returns whatever one TCP segment happened to carry. That made
/// two ports running the SAME canned service hash differently whenever one response
/// arrived split, which silently broke BOTH cross-port discriminators: bulk-dedup
/// stopped clustering them, and reconnect-consistency compared a whole response
/// against a truncated one. Measured: a host serving one identical page on 147
/// ports had 4 of them reported as real services.
///
/// Bounded twice over — a short idle gap ends the drain, and `MAX_BODY` caps it —
/// so a chatty or endless service cannot hold the scan open.
async fn drain(stream: &mut TcpStream, buf: &mut [u8], into: &mut Vec<u8>, idle: Duration) {
    loop {
        if into.len() >= MAX_BODY {
            return;
        }
        match timeout(idle, stream.read(buf)).await {
            Ok(Ok(0)) => return,            // EOF: the response is complete
            Ok(Ok(n)) => into.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => return,           // reset mid-response
            Err(_) => return,               // idle gap: it has said all it intends to
        }
    }
}

/// Enough to identify any protocol; far less than a page worth of HTML.
const MAX_BODY: usize = 8192;
/// The longest truemap waits for a server to speak first. Generous for one RTT.
const GREET_CAP: Duration = Duration::from_millis(800);
/// The idle gap that ends a drain. Short, because this runs per responsive port.
const DRAIN_IDLE: Duration = Duration::from_millis(150);

/// The HTTP probe, carrying the REAL target name.
///
/// This used to hardcode `Host: truemap.probe`. Measured against a real web server — a
/// name-based virtual host answers a bogus Host with `400 Bad Request` and the real
/// name with the application's own `301`. Both are HTTP, so coherence still worked,
/// but the evidence recorded was a generic error page instead of the service's actual
/// answer, and a stricter vhost can simply drop the connection.
fn http_probe(host: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: truemap\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes()
}

/// A minimal TLS 1.2+ ClientHello with SNI.
///
/// Chosen as the second probe because it draws a coherent reply out of *both*
/// kinds of server: a TLS listener answers with a ServerHello or an Alert, and a
/// plaintext HTTP listener answers `HTTP/1.1 400 Bad Request`. One probe, two
/// protocols covered.
fn client_hello(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut ext_sni = Vec::new();
    ext_sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // server_name_list len
    ext_sni.push(0x00); // host_name
    ext_sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    ext_sni.extend_from_slice(host);

    let mut exts = Vec::new();
    if !host.is_empty() && sni.parse::<IpAddr>().is_err() {
        exts.extend_from_slice(&[0x00, 0x00]); // ext type: server_name
        exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_sni);
    }
    // supported_versions: TLS 1.3, 1.2
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
    // supported_groups: x25519, secp256r1
    exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    // ec_point_formats: uncompressed
    exts.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    // signature_algorithms
    exts.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x01, 0x08, 0x04, 0x02, 0x01,
    ]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    body.extend_from_slice(&[0x5a; 32]); // random (fixed: we never complete the handshake)
    body.push(0x00); // session id len
    let ciphers: &[u8] = &[
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x30, 0x00, 0x9c,
        0x00, 0x2f, 0x00, 0x35,
    ];
    body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    body.extend_from_slice(ciphers);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![0x01]; // ClientHello
    let n = body.len();
    hs.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// A DNS query for the root NS records, framed for TCP.
///
/// Root NS is deliberate: a recursive resolver answers it, and an authoritative-only
/// server answers REFUSED. Both are DNS replies, which is the question being asked —
/// "is a nameserver here", not "will it serve me".
fn dns_query() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&DNS_TXID);
    msg.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT 1
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR 0
    msg.push(0x00); // QNAME: the root
    msg.extend_from_slice(&[0x00, 0x02]); // QTYPE NS
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&msg);
    out
}

/// Which second-stage payload to send if the port does not greet us.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    Http,
    Tls,
    /// Bare CRLFs — some line protocols only answer once you nudge them.
    Newline,
    /// A real DNS query over TCP. Port 53 speaks neither HTTP nor TLS, so without
    /// this a working nameserver is only ever "open, protocol unknown".
    Dns,
}

pub struct ProbeCfg {
    pub connect_timeout: Duration,
    pub greet_timeout: Duration,
    pub read_timeout: Duration,
    /// SNI / Host value for probes.
    pub sni: String,
}

/// Run one connection's worth of the ladder and return what we saw.
pub async fn probe(ip: IpAddr, port: u16, payload: Payload, cfg: &ProbeCfg) -> Signature {
    let addr = SocketAddr::new(ip, port);
    let t0 = Instant::now();
    let stream = match timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        // An immediate error is an ANSWER: the host (or a router on the way) told us
        // no. Collapsing this into the timeout case is what made a host that RSTs
        // every port report as "no response".
        Ok(Err(_)) => return Signature::unreachable(Dial::Refused),
        Err(_) => return Signature::unreachable(Dial::TimedOut),
    };
    let connect_ms = t0.elapsed().as_millis() as u64;
    let _ = stream.set_nodelay(true);
    let mut stream = stream;

    let mut buf = vec![0u8; 4096];
    let mut buf2 = vec![0u8; 4096];
    let mut data: Vec<u8> = Vec::new();
    let mut spoke = Spoke::Nothing;
    let mut close = Close::HeldOpen;

    // Stage 1: does it greet us? (ssh, smtp, ftp, mysql, imap, ...)
    //
    // CAPPED, deliberately. A server-first protocol sends its banner within about one
    // round trip; waiting the full connect timeout buys nothing and actively hurts,
    // because many web servers close an idle connection after a second or two and that
    // ends the ladder before the probe is ever sent. A late banner is not lost: it
    // arrives at the head of the buffer and is still what `coherent` reads.
    let greet = cfg.greet_timeout.min(GREET_CAP);
    match timeout(greet, stream.read(&mut buf)).await {
        Ok(Ok(0)) => {
            // Clean EOF with no data: the classic `tcpwrapped` shape. A real service
            // behind tcpwrappers looks like this, and so does a middlebox that
            // accepts then immediately drops.
            close = Close::EofNoData;
        }
        Ok(Ok(n)) => {
            data.extend_from_slice(&buf[..n]);
            // Take the WHOLE greeting, not just the first segment of it.
            drain(&mut stream, &mut buf2, &mut data, DRAIN_IDLE).await;
            spoke = Spoke::Greeting;
        }
        Ok(Err(_)) => close = Close::Reset,
        Err(_) => {} // silent so far; fall through to stage 2
    }

    // Stage 2: it did not greet us and the connection is still usable — nudge it.
    if data.is_empty() && close == Close::HeldOpen {
        let body: Vec<u8> = match payload {
            Payload::Http => http_probe(&cfg.sni),
            Payload::Tls => client_hello(&cfg.sni),
            Payload::Newline => b"\r\n\r\n".to_vec(),
            Payload::Dns => dns_query(),
        };
        let wrote = timeout(cfg.read_timeout, stream.write_all(&body)).await;
        match wrote {
            Ok(Ok(())) => {
                let _ = timeout(cfg.read_timeout, stream.flush()).await;
                match timeout(cfg.read_timeout, stream.read(&mut buf)).await {
                    Ok(Ok(0)) => close = Close::EofNoData,
                    Ok(Ok(n)) => {
                        data.extend_from_slice(&buf[..n]);
                        drain(&mut stream, &mut buf2, &mut data, DRAIN_IDLE).await;
                        spoke = match payload {
                            Payload::Http => Spoke::HttpProbe,
                            Payload::Tls => Spoke::TlsProbe,
                            Payload::Newline | Payload::Dns => Spoke::HttpProbe,
                        };
                        close = Close::EofAfterData;
                    }
                    Ok(Err(_)) => close = Close::Reset,
                    Err(_) => close = Close::HeldOpen, // accepted, took our data, said nothing
                }
            }
            // A write that fails or never completes: reset, or a zero-window stall.
            Ok(Err(_)) => close = Close::Reset,
            Err(_) => close = Close::HeldOpen,
        }
    } else if !data.is_empty() {
        // It greeted us and `drain` already took the rest, so the only question left
        // is whether the connection then ended.
        match timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
            Ok(Ok(0)) => close = Close::EofAfterData,
            Ok(Ok(_)) => close = Close::EofAfterData,
            Ok(Err(_)) => close = Close::Reset,
            Err(_) => close = Close::HeldOpen,
        }
    }

    let _ = stream.shutdown().await;

    // IT CLOSED ON US BEFORE WE SAID ANYTHING. That is not "no service" — it is a
    // server with a header-read timeout, and the ladder stopped before the probe was
    // sent. Measured: a web server that closes an idle connection after 1s was
    // reported `open-unidentified` with zero bytes while curl got a 301 from it, and
    // a real internet-facing host did the same. Try once more, speaking immediately.
    if data.is_empty() && close == Close::EofNoData {
        if let Ok(Ok(mut s2)) = timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
            let _ = s2.set_nodelay(true);
            let body: Vec<u8> = match payload {
                Payload::Http => http_probe(&cfg.sni),
                Payload::Tls => client_hello(&cfg.sni),
                Payload::Newline => b"\r\n\r\n".to_vec(),
                Payload::Dns => dns_query(),
            };
            if timeout(cfg.read_timeout, s2.write_all(&body)).await.is_ok() {
                let _ = timeout(cfg.read_timeout, s2.flush()).await;
                if let Ok(Ok(n)) = timeout(cfg.read_timeout, s2.read(&mut buf)).await {
                    if n > 0 {
                        data.extend_from_slice(&buf[..n]);
                        drain(&mut s2, &mut buf2, &mut data, DRAIN_IDLE).await;
                        spoke = match payload {
                            Payload::Http | Payload::Newline => Spoke::HttpProbe,
                            Payload::Tls => Spoke::TlsProbe,
                            Payload::Dns => Spoke::HttpProbe,
                        };
                        close = Close::EofAfterData;
                    }
                }
            }
            let _ = s2.shutdown().await;
        }
    }

    Signature {
        connected: true,
        dial: Dial::Connected,
        connect_ms,
        bytes: data.len(),
        hash: sig_hash(&data),
        proto: coherent(&data),
        spoke,
        close,
        sample: sample_of(&data),
    }
}

fn sample_of(data: &[u8]) -> String {
    data.iter()
        .take(120)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_a_well_formed_tls_record() {
        let ch = client_hello("example.com");
        assert_eq!(ch[0], 0x16, "TLS handshake record type");
        assert_eq!(&ch[1..3], &[0x03, 0x01]);
        let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(rec_len, ch.len() - 5, "record length must match body");
        assert_eq!(ch[5], 0x01, "ClientHello handshake type");
        let hs_len = ((ch[6] as usize) << 16) | ((ch[7] as usize) << 8) | ch[8] as usize;
        assert_eq!(hs_len, ch.len() - 9, "handshake length must match body");
        assert!(ch.windows(11).any(|w| w == b"example.com"), "SNI present");
    }

    #[test]
    fn no_sni_extension_for_a_bare_ip() {
        let ch = client_hello("10.0.0.1");
        assert!(!ch.windows(8).any(|w| w == b"10.0.0.1"), "must not SNI an IP literal");
    }

    /// Serve `chunks` with a pause between each, after reading whatever is sent.
    async fn serve_chunks(chunks: Vec<&'static [u8]>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut c, _)) = l.accept().await {
                let mut b = [0u8; 1024];
                let _ = timeout(Duration::from_millis(600), c.read(&mut b)).await;
                for ch in chunks {
                    let _ = c.write_all(ch).await;
                    let _ = c.flush().await;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                let _ = c.shutdown().await;
            }
        });
        port
    }

    fn cfg() -> ProbeCfg {
        ProbeCfg {
            connect_timeout: Duration::from_millis(1500),
            greet_timeout: Duration::from_millis(1200),
            read_timeout: Duration::from_millis(1500),
            sni: "127.0.0.1".into(),
        }
    }

    /// THE REGRESSION. A single `read()` returns one TCP segment, so the same canned
    /// response hashed differently depending on how it happened to be split. That
    /// broke bulk-dedup and reconnect-consistency at once: a uniform-fake host
    /// serving ONE identical page on 147 ports had 4 of them reported as real.
    #[tokio::test]
    async fn a_response_split_across_segments_hashes_the_same_as_one_sent_whole() {
        const WHOLE: &[u8] = b"HTTP/1.1 200 OK\r\nServer: canned-fake\r\nContent-Length: 0\r\n\r\n";
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let split = serve_chunks(vec![
            b"HTTP/1.1 200 OK\r\n",
            b"Server: canned-fake\r\n",
            b"Content-Length: 0\r\n\r\n",
        ])
        .await;
        let one = serve_chunks(vec![WHOLE]).await;

        let a = probe(ip, split, Payload::Http, &cfg()).await;
        let b = probe(ip, one, Payload::Http, &cfg()).await;

        assert_eq!(a.proto, Some(Proto::Http), "split response must still parse");
        assert_eq!(b.proto, Some(Proto::Http));
        assert_eq!(a.bytes, WHOLE.len(), "the WHOLE response must be read, got {}", a.bytes);
        assert_eq!(
            a.hash, b.hash,
            "identical bytes must hash identically however they are segmented — \
             otherwise bulk-dedup cannot cluster two copies of one fake"
        );
    }

    /// THE REGRESSION. A server with a header-read timeout closes an idle connection,
    /// which ended the ladder before the probe was ever sent: the port was reported
    /// `open-unidentified` with ZERO bytes while curl got a 301 from it. Seen against
    /// a real internet-facing web server and reproduced locally.
    #[tokio::test]
    async fn a_server_that_closes_an_idle_connection_is_still_identified() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = l.accept().await else { return };
                tokio::spawn(async move {
                    let mut b = [0u8; 2048];
                    // Wait only 150ms for a request, then hang up saying nothing —
                    // far shorter than any sane greeting wait.
                    match timeout(Duration::from_millis(150), c.read(&mut b)).await {
                        Ok(Ok(n)) if n > 0 => {
                            let _ = c
                                .write_all(
                                    b"HTTP/1.1 301 Moved Permanently\r\n                                      Location: https://x/\r\nContent-Length: 0\r\n\r\n",
                                )
                                .await;
                        }
                        _ => {}
                    }
                    let _ = c.shutdown().await;
                });
            }
        });
        let sig = probe("127.0.0.1".parse().unwrap(), port, Payload::Http, &cfg()).await;
        assert_eq!(
            sig.proto,
            Some(Proto::Http),
            "a server that hangs up on an idle connection must still be identified; \
             got {:?} with {} bytes",
            sig.proto,
            sig.bytes
        );
        assert!(sig.sample.contains("301"), "the real answer must be the evidence: {}", sig.sample);
    }

    #[tokio::test]
    async fn the_http_probe_carries_the_real_host_name() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            if let Ok((mut c, _)) = l.accept().await {
                let mut b = [0u8; 2048];
                let n = timeout(Duration::from_millis(900), c.read(&mut b))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&b[..n]).to_string());
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
                let _ = c.shutdown().await;
            }
        });
        let mut c = cfg();
        c.sni = "example.com".into();
        let _ = probe("127.0.0.1".parse().unwrap(), port, Payload::Http, &c).await;
        let req = rx.await.unwrap_or_default();
        assert!(
            req.contains("Host: example.com"),
            "a name-based vhost answers a bogus Host with 400 instead of the application's \
             own reply; request was: {req:?}"
        );
        assert!(!req.contains("truemap.probe"), "the placeholder Host must be gone");
    }

    #[tokio::test]
    async fn the_drain_is_bounded_so_an_endless_service_cannot_hold_the_scan_open() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut c, _)) = l.accept().await {
                let mut b = [0u8; 1024];
                let _ = timeout(Duration::from_millis(600), c.read(&mut b)).await;
                // Never stop talking.
                loop {
                    if c.write_all(&[b'x'; 2048]).await.is_err() {
                        return;
                    }
                }
            }
        });
        let started = std::time::Instant::now();
        let sig = probe("127.0.0.1".parse().unwrap(), port, Payload::Http, &cfg()).await;
        assert!(sig.bytes <= MAX_BODY, "must stop at the cap, read {}", sig.bytes);
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "an endless responder must not hold the probe open: took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn our_dns_query_is_well_framed_and_is_a_query() {
        let q = dns_query();
        let declared = u16::from_be_bytes([q[0], q[1]]) as usize;
        assert_eq!(declared, q.len() - 2, "TCP length prefix must frame the message");
        assert_eq!(&q[2..4], &DNS_TXID, "must carry the id the recognizer looks for");
        assert_eq!(q[4] & 0x80, 0, "QR bit clear: we send a query, not a reply");
        assert_eq!(u16::from_be_bytes([q[6], q[7]]), 1, "exactly one question");
        // Our own query must NOT be mistaken for a reply by the recognizer.
        assert!(!crate::coherent::dns_reply(&q));
    }

    #[test]
    fn a_refusal_and_a_timeout_are_not_the_same_answer() {
        // The whole liveness verdict turns on this: a RST proves the host is there.
        let r = Signature::unreachable(Dial::Refused);
        let t = Signature::unreachable(Dial::TimedOut);
        assert!(!r.connected && !t.connected, "neither completed a handshake");
        assert_ne!(r.dial, t.dial, "but they are not the same observation");
    }

    #[test]
    fn shape_ignores_timing() {
        let a = Signature {
            connected: true, dial: Dial::Connected, connect_ms: 3, bytes: 0, hash: 0, proto: None,
            spoke: Spoke::Nothing, close: Close::HeldOpen, sample: String::new(),
        };
        let mut b = a.clone();
        b.connect_ms = 900;
        b.sample = "noise".into();
        assert!(a.matches(&b), "timing and sample must not affect the shape");
    }
}
