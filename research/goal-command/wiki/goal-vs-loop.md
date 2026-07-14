# `/goal` vs `/loop`

Claude Code has two features for "keep at it" situations, and they solve *different* problems.
Picking the right one matters.

## The distinction in one line

- **`/goal`** — *persist toward a condition.* Work continuously, checking after each turn, until
  a stated end-state is reached. Iteration toward a finish line.
- **`/loop`** — *poll on a schedule.* Re-run a prompt or command at a set interval. Repetition
  on a clock.

## Side by side

| | `/goal <condition>` | `/loop <interval> <check>` |
|---|---|---|
| **Answers** | "Don't stop until X is true." | "Check X every N minutes." |
| **Trigger to continue** | End-of-turn check says *not yet met*. | The clock ticks. |
| **Stops when** | Condition met, judged impossible, or cleared. | You stop it (or its own logic exits). |
| **Cadence** | Continuous — works turn after turn. | Periodic — waits between runs. |
| **Built on** | A Stop hook that re-checks each turn. | A scheduled/recurring runner. |
| **Typical use** | "Fix all failing tests." | "Tell me when the deploy finishes." |

## How to choose

Ask: *am I iterating toward a finish line, or repeatedly checking a status?*

- **Iterating toward a finish line → `/goal`.** You want Claude to *do work and re-evaluate*
  until done. Example: "all tests green," "every endpoint documented."
- **Repeatedly checking a status → `/loop`.** The thing you're waiting on happens *elsewhere*
  and you just want to re-check it on a timer. Example: "is CI done yet?", "any new alerts?"

A useful signal: if the "check" is something Claude can *make progress on itself*, that's a
goal. If it's something Claude can only *observe* (an external job, a remote state), that's a
loop.

## Common mix-ups

- **"Keep checking until the build passes."** If Claude is the one *fixing* the build, that's a
  `/goal`. If the build is running elsewhere and Claude only watches, that's a `/loop`.
- **"Don't stop until everything's documented."** Iteration toward a condition → `/goal`.
- **"Ping me every 5 minutes with the queue depth."** Scheduled repetition → `/loop`.

> Claude Code's own suggestion system uses the same rule of thumb: phrasing like *"keep going
> until…"* points you to `/goal`, while repeated *"check again"* status requests point you to
> `/loop`. Each is offered only where its underlying machinery is available (hooks for `/goal`,
> the scheduler for `/loop`).
