# threat-dashboard

A threat hunting, detection and management desktop app — Zig + Vulkan +
Dear ImGui (docking), with the workspace/window framework ported from the
trading dashboard: snappable/dockable windows, tabs, F-key workspaces,
hotkeys, crash-safe layout persistence, a command line + fuzzy palette,
and a registry-generated HELP directory.

## Requirements

- **Zig 0.16.0+** (same toolchain the trading repo builds with)
- **LunarG Vulkan SDK ≥ 1.3.296** with the `VULKAN_SDK` env var set
  (Debug builds copy the validation layer next to the exe; `zig build
  vulkan-layers` forces just that step)
- Windows (renderer + persistence use win32 paths)

## Build & run

```sh
zig build          # builds zig-out/bin/threat-dashboard.exe
zig build run      # build + launch (mock world, seed 42)
zig build test     # unit tests (ui, domain, data, ai)
```

Useful flags:

| Flag | Effect |
|---|---|
| `--seed <u64>` | Mock-world seed — same seed ⇒ byte-identical world |
| `--state-dir <dir>` | Where `layout.ini` + `ui_state.json` live (default: cwd) |
| `--pg <conn-uri>` | Load the world from PostgreSQL instead of the mock generator |
| `--selftest` | Headless data-path + layout round-trip self-test (leak-gated) |
| `--mcp-check` | Spawn the threat-intel MCP server, list its tools, exit |
| `--validate` | Force-cycle every workspace/panel for a bounded run, then exit |
| `--screenshot <dir>` | `--validate` + one PNG per workspace |
| `--window WxH`, `--dpi-scale <f>`, `--mailbox`, `--demo` | See `--help` |

## Workspaces (F1–F5)

| Key | Workspace | Panels |
|---|---|---|
| F1 | TRIAGE | Posture Summary · Alert Queue · Cases · Timeline · Sensor Health · Log · Jobs |
| F2 | HUNT | Event Search · Timeline · Process Tree · Network · IOC List · Log · Jobs |
| F3 | DETECT | Detection Rules · ATT&CK Matrix · YARA Rules · Rule Tuning · Alert Queue · Log |
| F4 | INTEL | Intel Feeds · IOC List · IOC Enrichment · Threat Actors · Cases · Log |
| F5 | OPS | Sensor Health · Ingestion Stats · Jobs · Alert Queue · Log |

## Detection engineering & threat intel

- **YARA rules as code** (`YAR`, DETECT): a rule library with the
  7-field metadata policy and five CI gates per rule — compile
  (warnings-as-errors), metadata, true-positive fixture, false-positive
  corpus, and a 50 ms perf budget — rolled up into A–F quality grades.
  The ATT&CK matrix marks techniques covered by an active YARA rule.
- **IOC enrichment** (`ENR`, INTEL): verdict, multi-engine detection
  ratio, reputation, hosting/whois context, url-scan lifecycle, and
  pivots to contacted indicators. Deterministic mock data by default;
  the same shapes fill from live VirusTotal/urlscan lookups via the
  threat-intel MCP server.

## AI assistant

`Ctrl+Shift+A` opens an embedded Claude chat with an agentic tool-use
loop: read-only dashboard tools (alerts, events, IOCs, rules, YARA,
ATT&CK coverage, sensors) plus `ti_*` threat-intel tools proxied to
[threatintel-mcp](https://github.com/ChristianPresley) over stdio.
Configuration is environment-only:

```sh
set ANTHROPIC_API_KEY=...      # required — enables the assistant
set TD_AI_MODEL=claude-sonnet-5  # optional
set TD_MCP_CMD=threatintel-mcp --transport stdio  # optional override
set VT_API_KEY=... & set URLSCAN_API_KEY=...      # optional, live intel
```

All network I/O runs on a lazily-spawned worker thread; `--selftest`,
`--validate`, and CI never touch the network. Tools are read-only, and
threat-intel output is treated as untrusted and displayed defanged.

Every panel has a short CODE (`ALQ`, `EVT`, `RUL`, …) — type it into the
command line (`Ctrl+K` or `/`) and press Enter. `?` opens the HELP
directory with the full keyboard map. Panels drag/dock/tab freely
(ImGui docking); `RESET` rebuilds the active workspace's preset;
`Ctrl+S` snapshots layout + UI state.

## Data

v1 ships a **deterministic mock world** (diurnal telemetry + scripted
incident chains: phish → macro → PowerShell → C2 → cred dump → lateral
movement → exfil), so every panel is populated and cross-panel links
(Timeline brush → Event Search, ATT&CK cell → Rules, Event → Process
Tree) tell coherent stories.

### PostgreSQL

```sh
# one-time: seed a database with a mock world
threat-dashboard pgload --pg postgres://postgres:pass@localhost:5432/postgres

# run against it — panel actions (ack, rule toggles, case moves) write back
threat-dashboard --pg postgres://postgres:pass@localhost:5432/postgres
```

Schema lives in `src/data/schema.sql` (applied idempotently on connect).
If the database is unreachable the app degrades to the mock world with a
critical banner — the UI never dies with the DB.

## Layout persistence

ImGui's own ini writer is disabled; `src/ui/layout.zig` saves
`layout.ini` crash-safely (tmp file + atomic rename) every 60 s when
dirty, on workspace switch, and on exit. `ui_state.json` persists the
active workspace, seed, and filters.
