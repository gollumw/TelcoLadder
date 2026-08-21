# Security

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security tab → Report a
vulnerability** on this repository. Please do not open a public issue for
anything you believe is exploitable.

If that form is unavailable, contact the repository owner through the address
on their GitHub profile, with "TelcoLadder security" in the subject.

There is no bug bounty. You will get a reply, and credit in the fix if you want
it.

## Supported versions

There are no tagged releases yet. Only the `master` branch is supported.

## What the attack surface actually is

TelcoLadder is a **local** tool that runs `tshark` on files the user points it
at. Two things follow from that.

**`telcoladder serve` is not a web service.** It binds `127.0.0.1` only and
rejects requests whose `Host` header is not a loopback address (DNS-rebinding
protection). It must never be exposed on a network interface: anyone who can
reach it can make it run `tshark` against any path the serving user can read.
Reports of the form "if I run it with `--host 0.0.0.0` then…" are out of
scope — that is the documented footgun, not a vulnerability.

**Uploaded captures touch disk.** They are written to the system temp
directory with mode `0600`, deleted when the session is released, after 15
minutes idle, and on `Ctrl-C` / `SIGTERM`. They survive `kill -9`; on the next
start the tool lists them and does *not* delete them, because it cannot know
whether another process still wants the file. Uploaded captures are frequently
customer data — that is why this is handled carefully.

## In scope

- Path traversal through any endpoint (static files are served from a fixed
  name→path whitelist, not a directory; a bypass of that is in scope).
- Bypassing the `Host` check.
- Injecting arguments into the `tshark` invocation through display filters,
  decode-as rules, or file paths.
- Temp-file permission or lifetime issues that leave an uploaded capture
  readable by another user on the same host.
- Anything that lets the browser UI read a file the user did not select.

## Out of scope

- Running `serve` on a non-loopback interface.
- Vulnerabilities in `tshark` itself — report those to the Wireshark project.
  (We do pass user-supplied captures to it, so a tshark parser crash on a
  hostile pcap will crash a TelcoLadder analysis; that is expected and not
  something this project can fix.)
- Multi-user hardening on a shared host. The tool assumes the user account
  running it is the only one that matters.
