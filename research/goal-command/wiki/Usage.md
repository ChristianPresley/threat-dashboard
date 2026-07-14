# Usage

## Syntax

```
/goal <condition>     set an objective and begin working toward it
/goal active          display the current objective and how long it has been running
/goal clear           stop early and drop the objective
/goal                 with no argument: show status and usage
```

`<condition>` is free-form natural language. Write it the way you'd describe "done" to a
teammate — a checkable end-state, not a task list.

## Setting a goal

```
/goal all unit tests pass and `npm run lint` reports no errors
```

Claude acknowledges the objective and starts working. From that point on, at the end of each
turn it evaluates whether your condition is satisfied. If not, it keeps going; if so, it stops
and reports success. You don't need to type "continue" — that's the whole point.

### Tips for writing a good condition

- **Make it binary.** Prefer "all tests pass" over "improve the tests."
- **Name the check when you can.** "`pytest` exits 0" is easier to judge than "tests look fine."
- **Bound it.** "the three files in `src/broken/` compile" beats "fix the code."
- **One finish line.** Combining several with "and" is fine, but each clause should be checkable.

## Inspecting a running goal

```
/goal active
```

Shows the current objective and status while it's in progress. Useful if you've stepped away
and want to confirm what Claude is still working toward.

## Stopping early

```
/goal clear
```

Drops the objective immediately. Claude stops treating the condition as a gate and returns to
normal turn-by-turn operation. Use this if you've changed your mind, the goal was mis-stated,
or you want to take over manually.

## A worked example

```
You:    /goal every file in src/api exports a typed handler and the build passes
Claude: (works: adds types to handler 1, rebuilds — build still failing)
        → not yet met, continues
Claude: (types handler 2, rebuilds — still one untyped export)
        → not yet met, continues
Claude: (types handler 3, rebuilds — build passes, all exports typed)
        → condition satisfied → "Goal achieved"
```

If instead a required file simply didn't exist, Claude is designed to recognize the goal can't
be reached and stop with **"Goal could not be achieved,"** explaining the blocker — rather than
looping forever.

## Non-interactive use

`/goal` is also available outside the interactive terminal (for example, headless or
thin-client contexts), where the objective is supplied as text rather than typed into the TUI.
Behavior is the same: set a condition, work until met. See
[Requirements & Availability](Requirements-and-Availability) for where each form applies.
