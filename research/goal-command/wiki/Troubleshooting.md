# Troubleshooting

Symptoms and fixes, grouped by what you're seeing.

## `/goal` isn't available / doesn't appear

**Most likely: hooks are disabled, the workspace isn't trusted, or your build predates the
feature.** Work through these in order:

1. **Update Claude Code.** `/goal` was introduced in a specific build; older versions simply
   don't have it. Check your version and update.
2. **Check workspace trust.** `/goal` installs a hook and only trusted workspaces may do that.
   Accept the trust dialog (restart and re-trust if necessary).
3. **Check that hooks are enabled.** If a "disable all hooks" or "managed hooks only" setting is
   active — from your own settings or from policy — `/goal` can't run and won't be suggested.
   Re-enable hooks or adjust the policy. See
   [Requirements & Availability](Requirements-and-Availability).

## It refuses to start with a message about trust or hooks

That's expected and self-explanatory: it's telling you which precondition is unmet.

- **Trust message** → accept workspace trust and retry.
- **Hooks-restricted message** → hooks are turned off by a setting or policy; re-enable them.

Neither is a bug; both are the safeguards described in
[Requirements & Availability](Requirements-and-Availability).

## It stops too early / says "could not be achieved"

The end-of-turn check judged the condition **impossible** given the current situation. Usually
one of:

- **The condition can't literally be satisfied** — it references something missing or
  contradictory. Read the reason it printed; it names the blocker.
- **The condition is ambiguous** and the check read it more strictly than you meant. Re-state
  it more concretely and set it again.
- **The finish line was already unreachable** when you set it. Fix the underlying blocker first,
  then re-issue the goal.

**Fix:** make the condition checkable and achievable, then `/goal <condition>` again. See the
condition-writing tips in [Usage](Usage).

## It never seems to stop / keeps going

- **The condition isn't checkable.** If there's no objective yes/no ("make it better"), the
  check can't confidently say "met," so it keeps continuing. Re-state with a concrete finish
  line.
- **It's genuinely still working.** Long goals take many turns. Run `/goal active` to confirm
  what it's pursuing and how long it's been at it.
- **Safety cap.** Claude Code limits how many times a turn can be blocked in a row; a goal that
  can't progress will eventually hit that bound and end rather than loop forever (see
  [How It Works](How-It-Works)).

**Fix:** if it's the first case, `/goal clear` and re-state a checkable condition. If you just
want out, `/goal clear` stops it immediately.

## It met the goal but I disagree

The check decides "met" from the visible state of the work, and it can be over-eager on a
loosely-worded condition. Tighten the wording — name the exact test, file, or command that
must pass — and run it again. Specific conditions produce more reliable verdicts.

## I want to hand it off / take over

`/goal clear` drops the objective and returns Claude to normal turn-by-turn operation. Nothing
else is affected.

---

If none of this fits, the [How It Works](How-It-Works) page explains the underlying model, and
[`/goal` vs `/loop`](goal-vs-loop) covers the frequent case where `/loop` was actually the
right tool.
