# Security

## The boundary

SIP2Shell is working exploit code. It exists so researchers, red teams, and
defenders can reproduce CVE-2026-116779 on systems they are allowed to touch:
your own lab, an engagement scope, or an authorized bug-bounty target.

Do not run it against hosts you do not own or have written permission to test.
If you find a vulnerable third-party FreeSWITCH, report it to the operator or
the relevant CERT. Do not run the exploit to "prove" it.

## Reporting a bug in SIP2Shell

Use GitHub's private vulnerability reporting on this repository
(Security -> Report a vulnerability). Please do not open a public issue for a
bug that could crash a user's host or expose their callback listener.

Useful reports include:

- a crash, hang, or incorrect parse in `sip2shell.py`
- a bug in the OOB listener, the digest handling, or the SOCKS5 client
- a lab script that boots the wrong image or exposes more than it should
- documentation that could lead someone to test a host they do not own

The FreeSWITCH vulnerability itself is SignalWire's: see
GHSA-mg63-h38w-8p9p. This repository is not the place to report it.

## Supported versions

0.1.x on Python 3.8 and newer. The tool has no runtime dependencies; the demo
renderer in `scripts/` needs Pillow, but it is not part of the exploit path.
