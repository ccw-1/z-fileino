# z-fileinfo

Query file information on a remote **z/OS USS** system over SSH using only
**BCP (Basic Control Program)** commands — no extra packages required on the
z/OS side.

## Features

- **Six query modes** covering every stage of z/OS file investigation
- **Program-object analysis** via `amblist`: ASCII/EBCDIC mode, binary type,
  AMODE, RMODE, XPLINK, external references
- **Works on any binary size** — streaming pipeline, no temp files;
  a 596 MB binary (`ibm-clang`) returns results in ~11 s
- **MCP server** built in — exposes all queries as an MCP tool
  (`z_fileinfo_query`) for AI agents and developer harnesses
- Single C source file, zero runtime dependencies beyond `ssh`

## Query modes

| Mode | Remote command | What it shows |
|------|---------------|---------------|
| `file` | `/bin/file <path>` | File type identification |
| `ls` | `ls -la <path>` | Detailed directory listing |
| `stat` | `ls -laT <path>` | Listing with z/OS CCSID tag (`T=on/off`) |
| `od` | `/bin/od -A x -t x1 -N 32 <path>` | First 32 bytes hex dump |
| `amblist` | `amblist LISTLOAD OUTPUT=MODLIST` | Program-object analysis |
| `all` | All five commands combined | Everything at once |

## amblist mode

Analyses a linked z/OS program object (USS executable or load module) and
reports:

- **Module summary** — MEMBER NAME, AMODE, RMODE, XPLINK, PO FORMAT,
  OS compat level
- **Binary type** — detected from ESD class names in the first 200 lines:
  - `G_CODE64` → **Go** binary
  - `C_@@QPPA2` → **XL C/C++** binary
  - neither → Assembler / PL/X / LE-runtime-only
- **ASCII/EBCDIC mode** — from PMARL word 18, byte[0], bit `0x20`:
  - bit set → binary runs in **ASCII mode** (ASCII XL C build, Go binary)
  - bit clear → binary runs in **EBCDIC mode** (EBCDIC XL C build, assembler)
- **External reference sample** — shows `@@Axxxxx` ASCII-mode DLL stubs vs
  plain POSIX names

### PMARL ASCII flag — technical background

The PDSE member directory extension (PMARL) stores a flags byte that the z/OS
loader reads to determine whether to activate ASCII execution mode.  The field
is at word 18 (byte offset 0x48 from the start of the PMARL block), bit `0x20`
of the first byte.  It is present in **all** linked program objects regardless
of compiler or language, making it a reliable cross-language discriminator.

| Binary | PMARL word 18 | byte[0] | `& 0x20` | Mode |
|--------|--------------|---------|----------|------|
| XL C EBCDIC build | `148FC3C3` | `0x14` | 0 | EBCDIC |
| XL C ASCII build | `240FC3C3` | `0x24` | 32 | ASCII |
| Go binary | `233FC3C3` | `0x23` | 32 | ASCII |

## Build

```sh
# Requires: gcc (or clang), POSIX make, ssh in PATH
make

# Optional: install to ~/local/bin (override PREFIX=)
make install PREFIX=/usr/local/bin
```

The `z-fileinfo-mcp` binary is a copy of `z-fileinfo`; the program detects
MCP mode from `argv[0]` (or the `--mcp` flag).

## Usage — CLI

```sh
# Default: /bin/file
z-fileinfo pok56 /u/ccw/hello

# With explicit mode
z-fileinfo pok56 -ls      /u/ccw/
z-fileinfo pok56 -stat    /u/ccw/hello
z-fileinfo pok56 -od      /u/ccw/hello
z-fileinfo pok56 -amblist /u/ccw/hello
z-fileinfo pok56 -all     /u/ccw/hello

# user@host form
z-fileinfo ccw@pok56 -amblist /u/ccw/passwd

# Help / version
z-fileinfo -help
z-fileinfo -version
```

SSH is invoked with `BatchMode=yes` and a 10-second `ConnectTimeout`; the
target must be reachable via key-based auth (no interactive prompts).

## Usage — MCP server

```sh
# Start as MCP server (stdio JSON-RPC 2.0)
z-fileinfo-mcp
# or
z-fileinfo --mcp
```

### Tool: `z_fileinfo_query`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | ✓ | `[user@]host` — SSH target reachable via `BatchMode=yes` |
| `filepath` | string | ✓ | Absolute or relative path on the remote z/OS system |
| `mode` | string | | `file` (default) \| `ls` \| `stat` \| `od` \| `amblist` \| `all` |

### Tool: `z_fileinfo_help`

Returns usage summary and mode descriptions.

### Example MCP request

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"z_fileinfo_query",
           "arguments":{"target":"pok56","filepath":"/u/ccw/hello","mode":"amblist"}}}
```

## Requirements

**Local machine** (where z-fileinfo runs):
- C11 compiler (`gcc` or `clang`)
- `ssh` in PATH, key-based auth configured for the z/OS host

**Remote z/OS side** (no installation needed):
- z/OS USS with BCP — `/bin/file`, `ls`, `/bin/od`, `amblist`, `head`, `awk`
  are standard BCP utilities present on every z/OS system

## z/OS notes

- `/bin/file` **hangs** on some z/OS Go binaries — only `amblist` mode is
  safe for program objects
- `ls -laT` shows the file's CCSID tag (e.g. `t IBM-1047 /path`)
- `amblist` output is EBCDIC with ASA printer-control in column 1; the
  streaming `head -200 | awk` pipeline kills `amblist` via SIGPIPE after
  collecting the needed fields — safe and fast for any binary size

## Version history

### v0.2.0
- `amblist` mode: PMARL-based ASCII/EBCDIC detection (cross-language)
- Binary type fingerprint from ESD class names (`G_CODE64`, `C_@@QPPA2`)
- Streaming `head -200 | awk` pipeline — handles any binary size (~11 s for
  596 MB `ibm-clang` vs previous hang)

### v0.1.0
- Initial release: `file`, `ls`, `stat`, `od`, `all` modes
- `amblist` mode with C_COPTIONS EBCDIC byte-pattern search (XL C only)
- MCP server (`z_fileinfo_query`, `z_fileinfo_help`)

## License

[MIT](LICENSE)
