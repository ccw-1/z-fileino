# Changelog

All notable changes to z-fileinfo are documented here.
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — 2026-09-30

### Added
- **PMARL-based ASCII/EBCDIC mode detection** — reads PMARL word 18,
  byte[0], bit `0x20` from the PDSE member directory extension.  Works for
  all z/OS program-object types: Go, XL C/C++, assembler, PL/X.
- **Binary type fingerprint** from ESD class names in the first 200 lines:
  `G_CODE64` → Go; `C_@@QPPA2` → XL C/C++; neither → Assembler/PL/X.

### Changed
- `amblist` mode rewired to a **streaming `head -200 | awk` pipeline** — no
  temp files, no multi-pass full-file scans.  A 596 MB binary (`ibm-clang`)
  now returns in ~11 s (previously hung indefinitely).
- Binary type detection switched from `C_CODE64`/`C_COPTIONS` (appeared at
  lines 400–600+, unreachable for large binaries) to `C_@@QPPA2` (always in
  first 200 lines of any XL C/C++ linked object).
- Makefile `PREFIX` default changed from a personal path to `/usr/local/bin`.

### Removed
- C_COPTIONS EBCDIC pattern search section (superseded by PMARL; required a
  temp file and binary `grep -f` pattern matching).
- `MAPPED attribute` section (unreliable discriminator).

---

## [0.1.0] — 2026-09-28

### Added
- Initial release.
- Query modes: `file` (`/bin/file`), `ls` (`ls -la`), `stat` (`ls -laT`),
  `od` (`/bin/od -A x -t x1 -N 32`), `all` (all four combined).
- `amblist` mode: module summary (MEMBER NAME, AMODE, RMODE, XPLINK, PO FORMAT,
  OS compat level), C_COPTIONS EBCDIC byte-pattern search for ASCII/EBCDIC
  discrimination (XL C only), external reference (ER) record sample.
- MCP server (stdio JSON-RPC 2.0): `z_fileinfo_query` and `z_fileinfo_help`
  tools.
- Single C source file (`z-fileinfo.c`), no runtime dependencies beyond `ssh`.
