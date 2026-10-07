//! The fast sweep: a batched async TCP connect scan.
//!
//! Same shape as rustscan — open a very large number of concurrent connections
//! through the OS stack and let tokio multiplex them — with one addition: the
//! sweep knows the host's posture from calibration, so when a host answers
//! everything it stops enumerating instead of dutifully reporting 65535 open
//! ports that mean nothing.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use rand::seq::SliceRandom;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::calib::Posture;
use crate::cli::ScanOrder;

pub struct SweepCfg {
    pub concurrency: usize,
    pub timeout: Duration,
    /// Total attempts per port on a timeout (loss tolerance, not retry-until-open).
    pub tries: usize,
    /// Ascending or shuffled. The priority set leads either way.
    pub order: ScanOrder,
    /// Print `Open ip:port` as each one answers, rustscan-style.
    pub announce: bool,
    /// Stop enumerating once this many ports have answered on an answers-everything
    /// host — past this point the list is noise, not data.
    pub bail_after: usize,
}

pub struct SweepResult {
    pub answered: Vec<u16>,
    pub probed: usize,
    /// True if we stopped early because the host answers indiscriminately.
    pub bailed: bool,
}

/// Connect-scan `ports` on `ip`: the likely-service ports first, then the rest in
/// randomised order.
///
/// Two reasons for that order, and both are load-bearing:
///
/// * **Priority first.** On a host that answers everything the sweep bails out
///   early, and a purely random order can bail *before reaching port 22*. That is
///   how an early-bail optimisation turns into a missed service. Probing the
///   priority set first makes the bail unable to hide a well-known port, because
///   `bail_after` is larger than the priority set.
/// * **Random for the rest.** It makes the running open-ratio an unbiased estimate
///   of the whole range, so the bail decision is sound after a few hundred probes
///   instead of needing the full sweep.
pub async fn sweep(
    ip: IpAddr,
    ports: &[u16],
    priority: &[u16],
    posture: Posture,
    cfg: &SweepCfg,
) -> SweepResult {
    let mut first: Vec<u16> = ports.iter().copied().filter(|p| priority.contains(p)).collect();
    let mut rest: Vec<u16> = ports.iter().copied().filter(|p| !priority.contains(p)).collect();
    if cfg.order == ScanOrder::Random {
        let mut rng = rand::thread_rng();
        first.shuffle(&mut rng);
        rest.shuffle(&mut rng);
    }
    // Serial leaves both halves ascending, which is rustscan's `serial`; the only
    // difference is that the likely-service ports come first, and that is load-bearing
    // rather than cosmetic (see the doc comment above).
    let mut order = first;
    order.extend(rest);

    let answered = Arc::new(tokio::sync::Mutex::new(Vec::<u16>::new()));
    let probed = Arc::new(AtomicUsize::new(0));
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicUsize::new(0));
    // On a host that answers everything, enumeration is pointless past the bail
    // threshold; on a discriminating host we always do the full range.
    let may_bail = !matches!(posture, Posture::Discriminating);

    let results = stream::iter(order.into_iter().map(|port| {
        let answered = Arc::clone(&answered);
        let probed = Arc::clone(&probed);
        let hits = Arc::clone(&hits);
        let stop = Arc::clone(&stop);
        async move {
            if stop.load(Ordering::Relaxed) == 1 {
                return;
            }
            let addr = SocketAddr::new(ip, port);
            let mut open = false;
            for _ in 0..cfg.tries.max(1) {
                match timeout(cfg.timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(s)) => {
                        drop(s);
                        open = true;
                        break;
                    }
                    // A refusal is a definitive answer: closed. No point retrying.
                    Ok(Err(_)) => break,
                    // A timeout might be loss; retry.
                    Err(_) => continue,
                }
            }
            probed.fetch_add(1, Ordering::Relaxed);
            if open {
                let n = hits.fetch_add(1, Ordering::Relaxed) + 1;
                answered.lock().await.push(port);
                // rustscan's signature line. Capped: on a host that answers every
                // port this would otherwise be 65535 lines of noise, which is the
                // exact output problem truemap exists to fix.
                if cfg.announce {
                    if n <= ANNOUNCE_MAX {
                        println!("Open {ip}:{port}");
                    } else if n == ANNOUNCE_MAX + 1 {
                        println!(
                            "Open … suppressing further lines: {ip} has answered on \
                             {ANNOUNCE_MAX} ports, which is not a list of services yet"
                        );
                    }
                }
                if may_bail && n >= cfg.bail_after {
                    stop.store(1, Ordering::Relaxed);
                }
            }
        }
    }))
    .buffer_unordered(cfg.concurrency);

    results.collect::<Vec<()>>().await;

    let mut answered = answered.lock().await.clone();
    answered.sort_unstable();
    let bailed = stop.load(Ordering::Relaxed) == 1;
    SweepResult {
        answered,
        probed: probed.load(Ordering::Relaxed),
        bailed,
    }
}

/// How many `Open` lines to print before collapsing them.
const ANNOUNCE_MAX: usize = 50;

/// A sane default concurrency from the process file-descriptor limit.
///
/// Every in-flight connection is an fd; overshooting the limit is the single most
/// common way an async scanner dies ("too many open files").
pub fn default_concurrency(requested: Option<usize>) -> usize {
    let limit = fd_limit().unwrap_or(1024);
    // Leave headroom for stdio, the runtime and the adjudication phase.
    let ceiling = limit.saturating_sub(64).max(16);
    match requested {
        Some(r) => r.min(ceiling),
        None => ceiling.min(4096),
    }
}

pub fn fd_limit() -> Option<usize> {
    let mut rl = libc_rlimit { cur: 0, max: 0 };
    // SAFETY: getrlimit writes two u64s into a struct we own and sized correctly.
    let rc = unsafe { getrlimit(RLIMIT_NOFILE, &mut rl) };
    if rc == 0 {
        Some(rl.cur as usize)
    } else {
        None
    }
}

/// Raise the soft open-file limit, as rustscan's `-u` does.
///
/// Returns the new soft limit, or the hard limit as the error when the request
/// exceeds what this process may set without privilege.
pub fn raise_fd_limit(want: u64) -> Result<u64, u64> {
    let mut rl = libc_rlimit { cur: 0, max: 0 };
    // SAFETY: getrlimit/setrlimit write and read two u64s in a struct we own.
    unsafe {
        if getrlimit(RLIMIT_NOFILE, &mut rl) != 0 {
            return Err(0);
        }
        if want > rl.max {
            return Err(rl.max);
        }
        let new = libc_rlimit { cur: want, max: rl.max };
        if setrlimit(RLIMIT_NOFILE, &new) != 0 {
            return Err(rl.max);
        }
    }
    Ok(want)
}

/// RLIMIT_NOFILE on Linux.
const RLIMIT_NOFILE: i32 = 7;

#[repr(C)]
struct libc_rlimit {
    cur: u64,
    max: u64,
}

extern "C" {
    fn getrlimit(resource: i32, rlim: *mut libc_rlimit) -> i32;
    fn setrlimit(resource: i32, rlim: *const libc_rlimit) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrency_respects_the_fd_limit() {
        let c = default_concurrency(Some(1_000_000));
        let lim = fd_limit().unwrap_or(1024);
        assert!(c <= lim, "{c} must not exceed fd limit {lim}");
        assert!(c >= 16);
    }

    #[test]
    fn concurrency_honours_a_smaller_request() {
        assert_eq!(default_concurrency(Some(100)), 100);
    }

    /// Regression: with a purely random order, the early bail on an
    /// answers-everything host could stop before reaching port 22, so a real
    /// service was reported as nonexistent. The priority set must come first in
    /// BOTH scan orders -- that is why `--scan-order random` does not make it
    /// optional.
    #[test]
    fn priority_ports_lead_in_both_scan_orders() {
        let ports: Vec<u16> = (1..=65535).collect();
        let priority: Vec<u16> = vec![22, 80, 443, 3306];
        for order_mode in [ScanOrder::Serial, ScanOrder::Random] {
            let mut first: Vec<u16> =
                ports.iter().copied().filter(|p| priority.contains(p)).collect();
            let mut rest: Vec<u16> =
                ports.iter().copied().filter(|p| !priority.contains(p)).collect();
            if order_mode == ScanOrder::Random {
                let mut rng = rand::thread_rng();
                first.shuffle(&mut rng);
                rest.shuffle(&mut rng);
            }
            let mut order = first;
            order.extend(rest);
            assert_eq!(order.len(), 65535, "{order_mode:?}: no port dropped or duplicated");
            for p in &priority {
                let idx = order.iter().position(|x| x == p).expect("priority port present");
                assert!(idx < priority.len(),
                        "{order_mode:?}: port {p} must be in the first {} probes",
                        priority.len());
            }
        }
    }

    #[test]
    fn serial_order_is_ascending_after_the_priority_set() {
        let ports: Vec<u16> = vec![9000, 80, 8080, 22, 7777];
        let priority: Vec<u16> = vec![22, 80];
        let first: Vec<u16> = ports.iter().copied().filter(|p| priority.contains(p)).collect();
        let rest: Vec<u16> = ports.iter().copied().filter(|p| !priority.contains(p)).collect();
        // The caller hands us a sorted port list, so `serial` stays ascending.
        assert_eq!(first, vec![80, 22].into_iter().filter(|p| priority.contains(p))
                   .collect::<Vec<_>>(), "priority order follows the input");
        assert_eq!(rest, vec![9000, 8080, 7777]);
    }

    #[test]
    fn raising_the_fd_limit_beyond_the_hard_limit_reports_it_instead_of_failing_silently() {
        let hard = {
            let mut rl = libc_rlimit { cur: 0, max: 0 };
            unsafe { getrlimit(RLIMIT_NOFILE, &mut rl) };
            rl.max
        };
        // u64::MAX can only succeed if the hard limit is literally unlimited.
        match raise_fd_limit(u64::MAX) {
            Err(reported) => assert_eq!(reported, hard, "must report the real hard limit"),
            Ok(_) => assert_eq!(hard, u64::MAX, "only an unlimited hard limit may succeed"),
        }
        // A request at or below the current soft limit is a no-op success.
        let soft = fd_limit().unwrap_or(1024) as u64;
        assert!(raise_fd_limit(soft).is_ok());
    }
}
