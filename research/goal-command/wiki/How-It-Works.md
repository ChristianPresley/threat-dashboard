# How It Works

This page explains `/goal` in plain terms, using only Claude Code's **publicly documented**
[hooks system](https://code.claude.com/docs/en/hooks). No internal implementation detail is
required to understand the behavior — and none is reproduced here (see
[Methodology & Scope](Methodology-and-Scope)).

## The core idea: a check at the end of every turn

Claude Code supports **Stop hooks** — logic that runs at the moment Claude is about to finish a
turn. A Stop hook can do one of two things:

- **Allow** the stop — the turn ends normally, or
- **Block** the stop — Claude is pushed to keep working instead of ending.

`/goal` is built on exactly this mechanism. When you set a goal, it installs a Stop hook bound
to your condition. After each turn:

1. The hook runs a **model-based check**: given the conversation so far, is your condition
   satisfied? The check returns a yes/no plus a short reason.
2. **If yes** → the stop is allowed. Claude finishes and reports **"Goal achieved."**
3. **If the condition is judged impossible** → the goal ends as **"Goal could not be
   achieved,"** with the reason.
4. **If no (but still possible)** → the stop is **blocked**, and the reason is handed back to
   Claude as its next instruction. Claude keeps working, and the whole check repeats after the
   next turn.

That "block and hand the reason back" step is what makes Claude *keep working* — it's the
standard Stop-hook continuation behavior, applied automatically to your goal.

## The loop, at a glance

```
set goal ──► [ Claude works a turn ] ──► end-of-turn check
                    ▲                          │
                    │            met? ─────────┼─────────► YES ─► "Goal achieved"  (stop)
                    │                          │
                    │            impossible? ──┼─────────► YES ─► "Goal could not
                    │                          │                   be achieved"    (stop)
                    │                          │
                    └──────────  NO (keep working; reason fed back)
```

While a goal is active you'll typically see a brief status line after each turn — *working
toward the goal, not yet met, continuing* — until it resolves one way or the other.

## Why it doesn't loop forever

Two safeguards keep a goal from spinning indefinitely:

- **The "impossible" verdict.** The end-of-turn check can conclude the condition simply cannot
  be met (a required resource is missing, the request is contradictory, etc.) and stop with a
  failure result instead of continuing.
- **A continuation cap.** Claude Code's Stop-hook system limits how many times a turn can be
  blocked in a row before it gives up and ends the session — a general safety valve documented
  in the [hooks reference](https://code.claude.com/docs/en/hooks) (it also exposes the
  `stop_hook_active` state so a hook can tell it's already in a forced-continuation loop). A
  goal that can't make progress will hit this bound rather than run without end.

## What the check actually judges

The end-of-turn check looks at the **state of the work so far** and decides whether your
stated condition holds. Practical implications:

- **Checkable conditions work best.** The more objective your finish line, the more reliable
  the yes/no. "Tests pass" is easy to judge; "the code is elegant" is not.
- **The reason matters.** When the goal isn't met, the check's explanation becomes Claude's
  next marching order — so a well-scoped condition produces useful, targeted continuation.
- **Progress is tracked.** The system counts iterations as it goes, which feeds the safety cap
  above and the status you see on `/goal active`.

## Availability and gating

Because `/goal` relies on hooks, it only runs where hooks are permitted, and only in trusted
workspaces. Its availability can also depend on your Claude Code version and staged rollout.
Those conditions are covered in [Requirements & Availability](Requirements-and-Availability).
