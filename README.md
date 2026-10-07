# truemap

A fast TCP port scanner that determines which "open" ports are **real services** and
whether a host is **actually alive** — instead of reporting thousands of open ports that
have nothing behind them.

A SYN-ACK only means "open" if the host answers SYN *selectively*. Behind a SYN proxy, a
SYN-cookie firewall or a tarpit, every port answers, and conventional scanners report all
of them. truemap calibrates against ports it knows are closed on that same host, then
proves each candidate at the application layer before listing it.

The command-line interface is a drop-in match for [RustScan](https://github.com/RustScan/RustScan).

---

## Installation

### Quick install

```sh
git clone https://github.com/BakerWomack/truemap.git
cd truemap
./install.sh
```

The script installs a C linker and the Rust toolchain if either is missing, builds in
release mode, runs the unit tests, installs to `/usr/local/bin`, grants the capability
`--l4` needs, and verifies the result. It reports what it did rather than assuming
success.

| option | effect |
|--------|--------|
| `--prefix <DIR>` | install into `<DIR>/bin` instead of `/usr/local/bin` |
| `--no-setcap` | skip the `CAP_NET_RAW` grant; `--l4` will be unavailable |
| `--build-only` | build and test, install nothing |
| `--skip-tests` | do not run the unit tests |
| `-y`, `--yes` | do not prompt before installing system packages |
| `-h`, `--help` | usage |

It uses `sudo` only for the steps that require root, and falls back to `~/.local/bin`
when `/usr/local` is not writable and `sudo` is unavailable.

### Manual build

```sh
cargo build --release
sudo install -m0755 target/release/truemap /usr/local/bin/truemap
sudo setcap cap_net_raw+ep /usr/local/bin/truemap   # optional, enables --l4
cargo test                                          # 68 unit tests, no network needed
```

### Requirements

| | |
|---|---|
| **OS** | **Linux only.** `src/sweep.rs` uses the Linux value of `RLIMIT_NOFILE`, and `--l4` needs `AF_INET`/`SOCK_RAW` plus file capabilities. `install.sh` refuses to build elsewhere rather than produce a binary that misreads its own fd limit. |
| **Rust** | Edition 2021, stable toolchain. Installed by `install.sh` via [rustup](https://rustup.rs) if absent. |
| **C linker** | `cc` — every dependency is pure Rust, but `rustc` shells out to link. |
| **Optional** | `libcap2-bin` (for `setcap`), to enable `--l4`. Everything else works without it. |
| **nmap** | Optional, only for the `-- <nmap args>` hand-off. |

> **`setcap` is per-inode, so `cargo build` drops it.** The installer grants the
> capability to the *installed* binary, which a rebuild leaves alone. If you run
> `target/release/truemap` directly, re-run `setcap` after every build or `--l4` will
> silently report that raw sockets are unavailable.
>
> **File capabilities are inert on a filesystem mounted `nosuid`** — common for `/tmp`
> and for some container and home-directory mounts. There `setcap` succeeds and `getcap`
> reports `cap_net_raw=ep`, yet the kernel still refuses the raw socket. `install.sh`
> therefore tests `--l4` by running it rather than by reading `getcap`, and names the
> mount when it finds this.

---

## Usage

```sh
truemap 10.0.0.5                        # top 1000 ports
truemap -a 10.0.0.0/24 -r 1-1000        # a range across a CIDR
truemap 10.0.0.5 -p 22,80,443 -g        # greppable: 10.0.0.5 -> [22,80]
truemap 10.0.0.5 -r 1-65535 -- -A -sC   # proven ports -> nmap
truemap 10.0.0.5 --l4 --deep            # every answering port, plus the raw SYN-ACK test
```

```
$ truemap 10.0.0.5 -p 22,80,443,3306

  calibration  discriminating  (0/12 known-closed control ports answered, 12 refused / 0 dropped)
  sweep        4 ports probed, 2 answered at TCP
  liveness     ALIVE (service confirmed)
  22/ssh, 80/http answered a real protocol. Closed ports on this host are actively refused
                (12 of 12 control ports), so the port list is trustworthy as it stands.

  PORT    VERDICT               EVIDENCE
  22      real:ssh              SSH-2.0-OpenSSH_9.6p1..
  80      real:http             HTTP/1.1 200 OK..Server: nginx..Content-Leng…
```

Exit status is `1` when no host could be shown to run a service, which is useful in
pipelines.

### Options

```
truemap [OPTIONS] [IPS_OR_HOSTS]... [-- <COMMAND>...]
```

**RustScan-compatible**

| option | description | default |
|--------|-------------|---------|
| `-a`, `--addresses <LIST>` | IPs, CIDRs or hostnames (also positional) | |
| `-x`, `--exclude-addresses <LIST>` | addresses to skip | |
| `-p`, `--ports <LIST>` | comma-separated ports: `80,443,8080` | |
| `-r`, `--range <START-END>` | a port range: `1-65535`; also `all`, `top1000`, `anchors` | |
| `--top` | the 1000 most common ports | *(default)* |
| `-e`, `--exclude-ports <LIST>` | ports to skip | |
| `-b`, `--batch-size <N>` | concurrency, capped at the fd limit | `4500` |
| `-t`, `--timeout <MS>` | before a port is assumed closed | `1500` |
| `--tries <N>` | attempts per port | `2` |
| `-u`, `--ulimit <N>` | raise `RLIMIT_NOFILE` before scanning | |
| `--scan-order <ORDER>` | `serial` or `random` | `serial` |
| `--scripts <WHICH>` | `default` or `none` | `default` |
| `-g`, `--greppable` | only `ip -> [ports]` (aliases `--grep`, `-q`, `--quiet`) | |
| `--accessible` | no ASCII art, no large text blocks | |
| `--udp` | accepted and refused with an explanation; truemap is TCP-only | |
| `-- <COMMAND>...` | nmap args; truemap appends `-Pn -p <proven ports>` | |

**truemap's own**

| option | description | default |
|--------|-------------|---------|
| `--controls <N>` | known-closed control ports per host | `12` |
| `--deep` | prove every answering port, not just likely-service ports | |
| `--l4` | also run the SYN-ACK window/options test (needs `CAP_NET_RAW`) | |
| `--json` | machine-readable output, including why each port failed | |
| `--show-fakes` | list fabricated ports instead of collapsing them | |
| `--bail-after <N>` | stop enumerating after N answers on an indiscriminate host | |

---

## Why this exists

Ask any connect- or SYN-scanner whether a port is open and it answers from one fact: a
SYN-ACK came back. Behind a SYN proxy, a SYN-cookie firewall (F5 SYNcookie, Fortinet,
SonicWall, AWS Global Accelerator) or a tarpit (LaBrea, netfilter `TARPIT`/`DELUDE`), the
host answers *every* SYN — and "open" stops carrying information.

Measured against a SYN-proxied test host running **no services at all**:

| tool | ports reported open (of 1000) | real services |
|------|------|------|
| `nmap -Pn -p1-1000` | **1000** | 0 |
| `naabu -p 1-1000` | **1000** | 0 |
| `truemap -p 1-1000` | **0** | 0 |

`nmap -sV` does better — it labels them `tcpwrapped` — but it still lists them as open,
gives no host-level verdict, and takes a long time to get there.

---

## How it works

### Calibration against a known-closed control

The missing piece in a conventional scanner is a **negative control**. truemap probes a
handful of randomly-chosen high ports *first* — ports almost certainly not listening —
and whatever those do defines what "closed" looks like **on this host**:

- **controls refuse** → the host discriminates. Normal scan semantics; trust the list.
- **controls answer** → the host answers everything. Layer-4 state is noise, and the
  control's behavioural signature is the template every fabricated port will match.

### The four discriminators

A port is called a service only if it survives all four, ordered by how hard each is to
fake:

1. **Control match** — does it behave *identically* to a port known to be closed? A
   measurement against a control, not an inference. (`src/calib.rs`)
2. **Protocol coherence** — a real service answers in a nameable protocol: an `SSH-2.0`
   banner, an HTTP status line, a TLS record, a `220` greeting. (`src/coherent.rs`)
3. **Reconnect consistency** — connect twice. A real service says the same thing; a
   `portspoof`-style randomiser does not. Digits are stripped first, so a greeting
   carrying a timestamp still compares equal to itself.
4. **Bulk dedup** — one coherent answer appearing on dozens of ports is a single fake
   served everywhere, not dozens of services.

A **third probe** runs only on ports that survive as `open-unidentified`: they completed
a handshake, spoke no protocol truemap recognises, and did not match a known-closed
control. Port 53 gets a real DNS-over-TCP query, since a nameserver speaks neither HTTP
nor TLS and would otherwise be permanently unidentifiable; anything else gets a bare
newline. That set is small on a discriminating host and **empty** on an
answers-everything one, so it cannot turn a 65535-port blanket scan into 65535 extra
connections.

### Liveness verdicts

The question actually being asked — *is it alive?* — is answered from evidence, not port
count:

| verdict | meaning |
|---------|---------|
| `ALIVE (service confirmed)` | a named protocol answered; the proof is listed |
| `ALIVE (… host fabricates open ports)` | real services found **and** the host answers everything — both true |
| `ALIVE-OPAQUE` | completes handshakes, but no service could be proven. Something is on the path; what is behind it is unknown |
| `ALIVE (reachable, no services in range)` | closed ports were actively **refused**. A RST is the host answering, so it is provably up with nothing listening in range |
| `NO RESPONSE (all probes dropped)` | nothing answered and nothing was refused. Dropped, filtered or dead — and truemap states that it cannot tell which |

Fabricated ports are collapsed into a count with a reason rather than printed in full:

```
$ truemap 10.0.0.9 --top          # SYN-proxied host running nothing

  calibration  answers-everything  (12/12 known-closed control ports answered, rtt ~0ms)
              "port open" carries no information on this host — every verdict below
              comes from the application layer.
  sweep        1000 ports probed, 1000 answered at TCP
  liveness     ALIVE-OPAQUE (answers at TCP, no service provable)

  no port could be shown to run a real service

  1000 fabricated / unprovable port(s) suppressed:
    phantom(matches-closed-control)    1000 ports
    why: behaviour identical to the known-closed control ports [51688, 49414, 49442]
            on this host (connect ok, no protocol, same close behaviour) — fabricated
  (host finished in 19.2s)
```

`--show-fakes` lists them individually.

### The layer-4 test (`--l4`)

`--l4` adds the TCP-layer test from *Uncovering Network Tarpits with Degreaser* (Alt,
Beverly & Dainotti, ACSAC 2014), using the paper's measured thresholds:

- **receive window < 20** — in the authors' backbone traces ~99.7% of real connections
  used a window > 512; LaBrea defaults to 10 and netfilter `TARPIT` to 5.
- **no TCP options**, with MSS excluded because middleboxes inject it — LaBrea and the
  netfilter plugin forge packets without the host stack, so they negotiate none. Under
  0.5% of real connections carry no options.

**Where this layer is blind, and why that is stated rather than hidden:** a SYN-cookie
proxy terminates TCP with a real stack, so it emits a normal window and a full option set
on every port. The layer-4 test correctly says "these all look real" and is simply
useless. When more than `MAX_REAL` (64) ports pass it, `discriminate()` returns nothing
rather than blessing a fabricated mass, and says so:

```
tcp-layer  421 ports returned a normal window and full TCP options — consistent with
           a SYN-cookie proxy that terminates TCP with a real stack. The layer-4
           discriminator is blind here and returns nothing; the application layer decides.
```

The application layer is the primary engine. `--l4` is corroboration.

---

## Design notes

### A response must be read whole

A single `read()` returns whatever one TCP segment carried, so the same canned response
hashed differently depending on how it happened to be split. That broke both cross-port
discriminators at once: bulk dedup stopped clustering two copies of one fake, and
reconnect consistency compared a whole response against a truncated one. Measured: a host
serving one identical page on 147 ports had 4 of them reported as real services.

Responses are now drained to completion, bounded twice over — a 150 ms idle gap ends the
drain and 8 KB caps it — so an endless responder cannot hold the scan open. Both
properties are pinned by tests.

### Refused is not the same as dropped

Both mean "not open", and collapsing them is how a scanner reports a live host as dead.
truemap records the connect outcome three ways — `Connected`, `Refused`, `TimedOut` — and
the calibration line shows the split:

```
calibration  discriminating    (0/12 control ports answered, 12 refused / 0 dropped)
liveness     ALIVE (reachable, no services in range)
             12 of 12 control ports were actively REFUSED, which is the host
             answering — it is up and reachable.
```

```
calibration  silent/filtered   (0/12 control ports answered, 0 refused / 12 dropped)
liveness     NO RESPONSE (all probes dropped)
```

This was a real defect: a host that RSTs every probe was reported `NO RESPONSE … cannot
tell dead from dropped`, about a host that had just answered twelve times. The evidence
was being discarded at the `connect()` call. A matched pair of regression tests —
RST-everything versus drop-everything — keeps the two verdicts distinct, since they
differ only in that one respect.

The distinction matters in the other direction too. A hardened firewall that **silently
drops** traffic to closed ports still gives a trustworthy port list: its closed ports time
out and its open ports complete a handshake, so "open" means open. What makes layer-4
state meaningless is a host that **fabricates** open ports, not one that declines to send
a RST. Conflating the two produced a report that announced "this host answers every port"
about a host where two of forty-two answered, and in the same run asserted its closed
ports were "actively refused" when none had been. Both were false statements in the
output rather than wrong verdict fields, which is why the posture now distinguishes
`Silent` from `Blanket` and the reasoning text is itself tested.

### Guarding against over-flagging

Over-flagging is the easier failure and the worse one, because it hides real services.
Two deliberate guards:

- A **silent port on a discriminating host is reported, not discarded**, as
  `open-unidentified`. Degreaser's Internet-scale result backs this: a lone
  half-responder in a subnet was almost always a real service, while hundreds of them
  meant a tarpit. **Scarcity is the signal.** A regression test fails the build if this
  guard breaks.
- A **small window with real TCP options is not called a tarpit** — that is a congested
  host, not a forged packet.

### Two instructive defects

Both were found by scanning the full 65535-port range against a host that answers
everything, the case spot-checks never exercise:

1. **`-p all` hung before sending a packet.** Control ports were picked by rejection
   sampling against the scan list; with every port in that list the loop never
   terminated. The exclusion is now a preference with a bounded budget and a documented
   fallback (`calib.rs`).
2. **The early bail hid real services.** On an answers-everything host the sweep stops
   once enough ports have answered; in randomised order it could stop *before reaching
   port 22*, so a host with working ssh and https was reported `ALIVE-OPAQUE` with zero
   services. The sweep now probes likely-service ports first, and anchor ports are
   adjudicated whether or not the sweep reached them (`sweep.rs`, `main.rs`).

The second is the instructive one: an optimisation that was correct about *enumeration*
was silently wrong about *evidence*.

A third, in the same spirit: the HTTP probe once sent a placeholder `Host:` header. A
name-based virtual host answers a bogus `Host` with `400 Bad Request` and the real name
with the application's own response, so coherence still worked — but the evidence
recorded was a generic error page instead of the service's actual answer. The probe now
carries the real target name, and a test asserts the placeholder is gone.

---

## Performance

Measured over a local bridge network, so these are engine timings rather than network
timings, plus one scan over the public internet:

| scan | time |
|------|------|
| `-p all` (65535), discriminating host | **6.7 s** |
| `-p 1-30000`, discriminating host | **4.7 s** |
| `-p all`, answers-everything host **with** 2 real services | 36 s (finds both) |
| `-p all`, answers-everything host, nothing behind it | 32 s (0 real, `ALIVE-OPAQUE`) |
| `--top` (1000), answers-everything host, nothing behind it | 19 s (0 real) |
| `-p top1000`, discriminating host | ~2 s |
| `-p all`, host that drops everything | ~8 s (bounded by the timeout, not the host) |
| `scanme.nmap.org -p anchors` over the public internet (IPv6) | 5.5 s |

The sweep is the cheap part. On an answers-everything host the cost is application-layer
adjudication — two connections per candidate, each waiting out a timeout on a port that
will never speak. That is the price of not misreporting the result.

---

## Differences from RustScan

An existing RustScan command works unchanged. Four behaviours differ, and each is loud
rather than silent:

- **`--tries` defaults to 2, not 1.** The liveness verdict turns on telling a refused
  port from a dropped one, and a single try makes ordinary packet loss look like a drop.
  One extra try is cheap; a wrong `NO RESPONSE` is not.
- **`--udp` is accepted and refused**, with an explanation. truemap is TCP-only: its
  method is completing a handshake and proving the service above it, and UDP has no
  handshake to calibrate against. The flag exists so a command asking for UDP fails
  loudly instead of quietly scanning TCP and labelling it UDP.
- **`--scan-order` is honoured, but likely-service ports always lead.** A correctness
  requirement, not a preference: on a host that answers everything the sweep bails early,
  and a purely random order can bail before reaching port 22.
- **No config file**, so `-c/--config-path` and `-n/--no-config` are absent rather than
  stubbed.

### The nmap hand-off

RustScan gives nmap every port that returned a SYN-ACK. truemap gives it only the ports
it **proved**. Against a SYN-proxied host:

| | ports handed to nmap | `nmap -sV` time | real services found |
|---|---|---|---|
| RustScan's hand-off | **1000** | ~14 min¹ | 0 |
| truemap's hand-off | **2** | 2.9 s | 2 |

¹ measured at 82 s for 100 of those ports and extrapolated; every one returns
`tcpwrapped`.

A user `-p` after `--` is dropped deliberately — honouring it would hand back the very
ports truemap just rejected.

**`--deep`, and why it is not the default.** On an answers-everything host every port
answers, and adjudicating all 65535 at two connections each is a denial of service
against yourself. By default truemap adjudicates the ports where real services actually
live (nmap's top 1000 plus an anchor set) and says so in the output. `--deep` proves
every answering port, which is the only way to find a real service on an arbitrary high
port behind a SYN proxy.

---

## Project layout

```
install.sh        toolchain + build + install + setcap + verify
src/
  main.rs         orchestration: sweep -> calibrate -> adjudicate -> report
  cli.rs          RustScan-compatible argument surface
  sweep.rs        the concurrent connect sweep, fd-limit aware, priority-first
  calib.rs        known-closed control ports and host posture
  probe.rs        the application-layer probe ladder (greet, HTTP, TLS, DNS)
  coherent.rs     protocol recognition and response normalisation
  adjudicate.rs   per-port verdicts: control match, reconnect, bulk dedup
  liveness.rs     the host-level verdict and its stated reasoning
  synack.rs       the privileged Degreaser-style SYN-ACK test (--l4)
  nmap.rs         the hand-off: proven ports only
  output.rs       human, greppable and JSON reports
  ports.rs        top-1000 and anchor port sets
  target.rs       IP / CIDR / hostname and port-spec parsing
```

68 unit tests cover parsing, the adjudication rules, the reasoning text, SYN packet
construction and the drain's boundedness. `cargo test` runs them in about a second and
needs no network.

---

## References

- Alt, Beverly & Dainotti, *Uncovering Network Tarpits with Degreaser*, ACSAC 2014 —
  [cmand.org](https://www.cmand.org/papers/degreaser-acsac14.pdf)
- F5, *Nmap port scan of Virtual Address can show all ports open when using SYNcookie
  Protection* — [my.f5.com](https://my.f5.com/manage/s/article/K04322145)
- AWS Global Accelerator SYN-proxy false positives —
  [thoughtfarmer.com](https://helpdesk.thoughtfarmer.com/hc/en-us/articles/50262164179987)
- Nmap, *`tcpwrapped` FAQ* — [secwiki.org](https://secwiki.org/w/FAQ_tcpwrapped)
- netfilter `xtables-addons` `TARPIT` / `DELUDE` targets

---

## Scope

truemap is a measurement tool for networks you are authorised to scan. It is deliberately
conservative, and sends fewer probes than the scanners it replaces, because its purpose
is to stop treating a SYN-ACK as a service.
