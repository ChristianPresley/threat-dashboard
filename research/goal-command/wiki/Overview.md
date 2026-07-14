# Overview

## What `/goal` is

`/goal` lets you hand Claude Code a **finish line** instead of a single instruction. You state
a condition — *"all tests pass", "the three broken files are fixed", "the changelog covers
every merged PR"* — and Claude keeps working toward it, re-checking after each turn, rather
than stopping after one pass and waiting for you to say "keep going."

It exists because a very common request — *"don't stop until X"* — is otherwise tedious: you
end up nudging Claude with "continue" over and over. `/goal` captures that intent once and
enforces it automatically until the condition is met.

## When to use it

Reach for `/goal` when **all** of these are true:

- There is a **clear, checkable end-state** you can describe in a sentence.
- The work is **iterative** — it may take several turns of doing-then-checking to get there.
- You want Claude to **self-check and continue** without you babysitting each turn.

Good conditions share one trait: a person (or a model) could look at the current state and
give a confident yes/no on whether they're satisfied.

**Well-formed goals**

- `/goal all unit tests pass and the linter is clean`
- `/goal every public function in src/api has a docstring`
- `/goal the migration script runs end-to-end with no errors`

**Poorly-formed goals** (vague, unbounded, or not checkable)

- `/goal make the code better` — no objective finish line
- `/goal keep improving performance` — no stopping point
- `/goal check if the deploy is done` — that's *polling a status*, not iterating toward a
  condition; use [`/loop`](goal-vs-loop) instead

## What it is not

- **Not a scheduler.** It doesn't run on a clock or wake up later; it works continuously until
  done. For "check every 5 minutes," see [`/goal` vs `/loop`](goal-vs-loop).
- **Not a guarantee.** If the condition can't be met, `/goal` is designed to recognize that and
  stop with a "could not be achieved" result rather than spin forever.
- **Not unbounded.** It works toward the goal but has a built-in stop so it can't loop forever
  (see [How It Works](How-It-Works)).

## The three ways a goal ends

| Outcome | Meaning |
|---|---|
| **Achieved** | The condition is judged satisfied. Claude stops; the goal is complete. |
| **Could not be achieved** | The condition is judged impossible given the situation. Claude stops and tells you why. |
| **Cleared** | You ran `/goal clear` (or otherwise stopped it) before it finished. |

See [Usage](Usage) for how to drive each of these, and [How It Works](How-It-Works) for what
happens between turns.
