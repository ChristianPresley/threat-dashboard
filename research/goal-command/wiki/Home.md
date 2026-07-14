# The `/goal` command — a user's guide

`/goal` is a Claude Code slash command that sets a **persistence condition**: you describe an
end-state in plain language, and Claude keeps working, checking after each turn, until that
condition is satisfied (or is judged impossible). It is Claude Code's built-in answer to
*"keep going until X."*

```
/goal <condition>     set an objective and start working toward it
/goal active          show the current objective
/goal clear           stop early / drop the objective
/goal                 show status / usage
```

This wiki documents `/goal` from the perspective of **someone using the feature** — what it
does, how to drive it, when to reach for it versus `/loop`, and how to fix it when it won't
run. It describes observable behavior and builds on the **publicly documented** Claude Code
hooks system; it does not reproduce any internal/proprietary implementation. See
[Methodology & Scope](Methodology-and-Scope) for exactly where that line sits.

## Start here

- **[Overview](Overview)** — what `/goal` is and when to use it
- **[Usage](Usage)** — syntax, sub-commands, worked examples
- **[How It Works](How-It-Works)** — the check-after-each-turn model, in plain terms
- **[Requirements & Availability](Requirements-and-Availability)** — what must be true for `/goal` to run
- **[`/goal` vs `/loop`](goal-vs-loop)** — persist-to-a-condition vs poll-on-a-schedule
- **[Troubleshooting](Troubleshooting)** — "it's not there", "it stops too early", "it never stops"
- **[Methodology & Scope](Methodology-and-Scope)** — how this was written and what it deliberately omits
- **[Bibliography](Bibliography)** — sources and further reading

## One-line mental model

> `/goal` turns a plain-language finish line into a check that runs at the end of every turn,
> and keeps Claude working until the check passes.

---
*Companion to the local research module under `research/goal-command/`. This wiki is the
behavior-level, publication-safe treatment; the deeper technical notes stay in the repo.*
