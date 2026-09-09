TelcoLadder - Windows x64 standalone executable (no-install portable zip)
=========================================================================

What this is
  telcoladder.exe and its runtime, built by CI from the tagged source. Nothing
  is installed and no registry key is written; delete the folder to remove it.

What it needs
  Wireshark 4.0 or newer on this machine, for tshark.exe. It is found in the
  default install location automatically, or point TELCOLADDER_TSHARK at
  tshark.exe. Nothing else.

First run
  Double-click check-environment.cmd. It runs `telcoladder.exe check` and tells
  you whether tshark and its dissectors were found.

Use
  telcoladder.exe summarize capture.pcapng        one page of facts, Markdown
  telcoladder.exe summarize capture.pcapng --json the same facts as JSON
  telcoladder.exe analyze capture.pcapng -o flow.mmd   Mermaid ladder
  telcoladder.exe serve                           browser at http://127.0.0.1:3005
  telcoladder.exe --help                          everything else

  The browser interface binds 127.0.0.1 only. Paste a path for large captures;
  nothing is copied and nothing leaves this machine.

Licence
  TelcoLadder: PolyForm Noncommercial License 1.0.0 (LICENSE). Free for
  personal, non-commercial and educational research use; commercial deployment
  requires a separate commercial licence - see README.md.
  This folder also contains the CPython runtime (PSF License) and PyYAML (MIT),
  redistributed under their own terms; the browser bundle's third-party
  packages are listed in NOTICE.
