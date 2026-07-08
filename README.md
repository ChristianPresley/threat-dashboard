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
| F5 | OPS | Sensor Health · Ingestion Stats · Data Pipelines · Jobs · Audit Trail · Alert Queue · Log |

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

## Data pipelines (dbt-style ELT)

`PIP` (OPS) manages data processing pipelines end to end: register
**sources** (PostgreSQL, MySQL, MSSQL, S3, Kafka, syslog, REST APIs, CSV
exports — with connection-state probes), chain **transform models**
following dbt conventions (`stg_*` staging views → `int_*` incremental
models → `mart_*` tables, with dedup/filter/enrich/join/aggregate/mask
step kinds and per-model materializations), and land the result in a
**sink** (PostgreSQL, Elasticsearch, ClickHouse, S3 Parquet, or a Kafka
topic). Each pipeline carries a **dbt-style test suite** (`not_null`,
`unique`, `accepted_values`, `relationships`, source `freshness`) whose
pass/fail results and failing-row counts surface next to the run
history (rows in → out, rejected rows, duration). A builder section
creates new pipelines from the registered sources; runs execute as
async jobs and mutations mirror to PostgreSQL through the same Store
write hook as everything else.

Pipelines run themselves: a **scheduler** auto-queues due runs (per the
pipeline's cadence), each pipeline carries a **watermark** (newest data
landed in the sink) whose lag drives the freshness tests, and rejected
rows spill into a **dead-letter queue** with per-row samples an analyst
can replay or drop. Sink health (last landing, rows/24h, watermark lag)
shows per pipeline.

## Jobs, audit, and SLA metrics

- **Job queue** (`JOB`, most workspaces): async work is a real queue —
  N concurrent slots, queued/running/done/failed/canceled states, FIFO
  promotion, cancel with cleanup (a canceled run/sync/enrichment never
  strands half-open state), and a bounded terminal history. Feed syncs
  run per-feed or fleet-wide; the retention sweep prunes old run
  history and resolved dead letters.
- **Audit Trail** (`AUD`, OPS): chain of custody — every analyst and
  system action (acks, rule toggles, case moves, pipeline operations)
  recorded at the Store mutation choke point with who · what · when.
  The record lives outside the swappable Store state, so PostgreSQL
  snapshot refreshes never erase it.
- **Triage SLAs** (`PST`): alerts carry ack/resolve timestamps; the
  posture summary shows real MTTA and MTTR computed from them.

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

After the boot load, a **background worker** owns the database
connection (`src/data/pg_worker.zig`): panel mutations queue to it
instead of blocking the render thread, and every 5 s it loads a fresh
snapshot the render thread swaps in — external writes (ingestion, other
analysts) appear without a restart. A mutation-sequence guard drops any
snapshot that raced a panel write, so a refresh can never revert an
action you just took. If the connection drops, the worker reconnects
with backoff and reloads database truth.

## Layout persistence

ImGui's own ini writer is disabled; `src/ui/layout.zig` saves
`layout.ini` crash-safely (tmp file + atomic rename) every 60 s when
dirty, on workspace switch, and on exit. `ui_state.json` persists the
active workspace, seed, and filters.
