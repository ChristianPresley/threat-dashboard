# Methodology & Scope

This page is deliberately explicit about **how this wiki was written** and **where its limits
are**, so readers know how much to trust each claim and what has been intentionally left out.

## What this wiki is

A **behavior-level** guide to the `/goal` command, written for people who want to *use* the
feature. Its claims come from two kinds of source:

1. **Observable behavior** — what `/goal` does when you run it: its sub-commands, the outcomes
   it reports, the conditions under which it refuses to start, and how it differs from `/loop`.
2. **Publicly documented mechanics** — Claude Code's [hooks system](https://code.claude.com/docs/en/hooks),
   especially Stop hooks, which `/goal` is built on. Where this wiki says "it blocks the stop
   and hands the reason back," that is the documented, public behavior of Stop hooks in general,
   applied to `/goal`.

Everything here is phrased in our own words, at the level a user needs.

## What this wiki is **not**, and why

This is **not** a reverse-engineering write-up. It intentionally **does not** include:

- verbatim internal prompt text or message strings,
- internal identifiers, event names, or feature-flag names,
- byte offsets, binary hashes, or extracted/de-minified source,
- any other proprietary implementation detail of Claude Code.

Those belong to Anthropic's commercial product. Reproducing them in a public document would be
redistributing proprietary material, so they're excluded on purpose. A user does not need any
of that to understand or operate `/goal` — the behavioral model on
[How It Works](How-It-Works) is sufficient.

## Confidence and caveats

- **Version-specific.** `/goal`'s presence and exact wording depend on your Claude Code build.
  Details here reflect the behavior of the version this was written against and may drift.
  Treat the official docs as authoritative if they differ.
- **Behavioral inference.** Statements about *why* `/goal` behaves a certain way (e.g. "it's a
  Stop hook, so it needs hooks enabled") are grounded in public documentation plus observed
  behavior, not in any privileged source.
- **No guarantees of internals.** Because implementation detail is deliberately out of scope,
  this wiki makes no claims about *how* the feature is coded — only about how it behaves.

## Corrections

If Claude Code's behavior has changed, or an item here is inaccurate, prefer the official
[Claude Code documentation](https://docs.claude.com/en/docs/claude-code/overview) and update
this page accordingly. See the [Bibliography](Bibliography) for the sources relied on.
