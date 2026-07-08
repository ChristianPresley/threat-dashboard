-- threat-dashboard PostgreSQL schema, applied statement-by-statement by
-- src/data/pg.zig migrate(). One statement per block. NOTE: the migrator
-- splits on semicolons, so comments must not contain one.
-- Timestamps are unix milliseconds (bigint) — the app renders UTC itself.
-- host/usr/sensor/technique are smallint indices into the app-side tables
-- (hosts/users rows carry the names; the ATT&CK technique table is static
-- in the binary).

create table if not exists hosts (
  id smallint primary key,
  name text not null
);

create table if not exists users (
  id smallint primary key,
  name text not null
);

create table if not exists sensors (
  id smallint primary key,
  host text not null,
  kind smallint not null,
  status smallint not null,
  eps real not null,
  lag_s real not null,
  last_seen_ms bigint not null,
  version text not null
);

create table if not exists feeds (
  id smallint primary key,
  name text not null,
  url text not null,
  last_sync_ms bigint not null,
  ioc_count int not null,
  status smallint not null
);

create table if not exists rules (
  id smallint primary key,
  code text not null,
  name text not null,
  status smallint not null,
  severity smallint not null,
  technique smallint not null,
  fires_7d int not null,
  fp_7d int not null,
  last_fire_ms bigint not null,
  author text not null,
  query text not null
);

create table if not exists iocs (
  id int primary key,
  type smallint not null,
  value text not null,
  confidence smallint not null,
  feed smallint not null,
  first_seen_ms bigint not null,
  last_seen_ms bigint not null,
  hits int not null
);

create table if not exists actors (
  id smallint primary key,
  name text not null,
  aliases text not null,
  motivation smallint not null,
  techniques text not null, -- csv of technique indices
  notes text not null
);

create table if not exists events (
  id bigint primary key,
  ts_ms bigint not null,
  kind smallint not null,
  severity smallint not null,
  host smallint not null,
  usr smallint not null,
  sensor smallint not null,
  parent bigint,
  technique smallint,
  process text not null,
  cmdline text not null,
  dst_ip text not null,
  dst_port int not null
);

create index if not exists events_ts_idx on events (ts_ms);

create index if not exists events_host_ts_idx on events (host, ts_ms);

create table if not exists alerts (
  id int primary key,
  ts_ms bigint not null,
  rule smallint not null,
  severity smallint not null,
  status smallint not null,
  technique smallint,
  title text not null,
  entity text not null,
  assignee text not null,
  case_id smallint,
  event_ids text not null -- csv of event ids
);

create index if not exists alerts_ts_idx on alerts (ts_ms);

create table if not exists cases (
  id smallint primary key,
  title text not null,
  severity smallint not null,
  status smallint not null,
  assignee text not null,
  opened_ms bigint not null,
  updated_ms bigint not null,
  alert_ids text not null, -- csv of alert ids
  notes text not null
);

create table if not exists yara_rules (
  id smallint primary key,
  code text not null,
  name text not null,
  status smallint not null,
  severity smallint not null,
  technique smallint not null,
  author text not null,
  date_ms bigint not null,
  description text not null,
  reference text not null,
  version smallint not null,
  strings_excerpt text not null,
  condition text not null,
  gate_compile smallint not null,
  gate_meta smallint not null,
  gate_tp smallint not null,
  fp_count int not null,
  scan_ms real not null,
  budget_ms real not null,
  last_ci_ms bigint not null
);

create table if not exists ioc_enrichment (
  ioc_id int primary key,
  status smallint not null,
  source smallint not null,
  fetched_ms bigint not null,
  err text not null,
  verdict smallint not null,
  det_malicious int not null,
  det_suspicious int not null,
  det_harmless int not null,
  det_undetected int not null,
  reputation int not null,
  threat_label text not null,
  first_seen_ms bigint not null,
  last_seen_ms bigint not null,
  registrar text not null,
  creation_ms bigint not null,
  categories text not null,
  asn bigint not null,
  as_owner text not null,
  country text not null,
  network text not null,
  scan_score smallint not null,
  brands text not null,
  page_domain text not null,
  page_ip text not null,
  tls_issuer text not null,
  pivot_ids text not null -- csv of ioc ids
);

create table if not exists urlscan_scans (
  id int primary key,
  ioc_id int not null,
  state smallint not null,
  submitted_ms bigint not null,
  completed_ms bigint not null,
  err text not null
);

create table if not exists data_sources (
  id smallint primary key,
  name text not null,
  kind smallint not null,
  dsn text not null,
  state smallint not null,
  last_test_ms bigint not null,
  latency_ms real not null,
  tables int not null
);

create table if not exists pipelines (
  id smallint primary key,
  code text not null,
  name text not null,
  source smallint not null,
  sink smallint not null,
  target text not null,
  schedule_min int not null,
  status smallint not null,
  steps text not null, -- pipe-separated kind,materialization,model triples
  tests text not null, -- pipe-separated kind,status,failures,target quads
  last_run_ms bigint not null,
  owner text not null
);

create table if not exists pipeline_runs (
  id int primary key,
  pipeline smallint not null,
  started_ms bigint not null,
  duration_ms bigint not null,
  rows_in bigint not null,
  rows_out bigint not null,
  rows_rejected bigint not null,
  status smallint not null,
  tests_passed smallint not null,
  tests_failed smallint not null,
  err text not null
);

create index if not exists pipeline_runs_pipe_idx on pipeline_runs (pipeline, started_ms);

-- Watermark columns arrived after the tables (idempotent add for existing DBs)
alter table pipelines add column if not exists watermark_ms bigint not null default 0;

alter table pipeline_runs add column if not exists watermark_ms bigint not null default 0;

create table if not exists dead_letters (
  id int primary key,
  pipeline smallint not null,
  run_id int not null,
  ts_ms bigint not null,
  kind smallint not null,
  target text not null,
  sample text not null,
  state smallint not null
);

create index if not exists dead_letters_pipe_idx on dead_letters (pipeline, state);

-- Triage SLA stamps arrived after the alerts table (idempotent add)
alter table alerts add column if not exists acked_ms bigint not null default 0;

alter table alerts add column if not exists resolved_ms bigint not null default 0;
