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
