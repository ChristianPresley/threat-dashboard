# Requirements & Availability

`/goal` doesn't run everywhere. Because it is built on Claude Code's hooks system, it inherits
that system's requirements, plus a couple of environment conditions. If `/goal` is missing or
refuses to start, one of the items below is almost always the reason.

## Requirements checklist

| Requirement | Why | If unmet |
|---|---|---|
| **Recent enough Claude Code** | `/goal` was added in a specific build; older versions don't have it. | Command doesn't appear at all. Update Claude Code. |
| **Trusted workspace** | `/goal` installs a hook, which only trusted workspaces may do. | It refuses with a trust-related message. Accept the workspace-trust prompt (you may need to restart and re-trust). |
| **Hooks enabled** | `/goal` *is* a Stop hook; if hooks are turned off it cannot function. | It refuses, pointing at the hooks restriction. See below. |
| **Feature rollout** | Availability can be gated by version/rollout. | May be present for some users/builds and not others. |

## The two hard gates

### 1. Trusted workspace

`/goal` will only run in a workspace you've marked as trusted. If you opened the folder in an
untrusted state, accept the trust dialog (restarting Claude Code and re-accepting it if
needed), then try again.

### 2. Hooks must be enabled

Since the command works by installing a Stop hook, it cannot run if hooks are disabled — for
example when a "disable all hooks" or "managed hooks only" setting is active, whether you set
it or it comes from policy. Re-enabling hooks (or adjusting the policy that disabled them)
restores `/goal`. See the [hooks documentation](https://code.claude.com/docs/en/hooks) for the
relevant settings.

> **Tip:** the same hooks requirement means that in a hooks-restricted environment, Claude Code
> won't even *suggest* `/goal` — so if you've never seen it offered, check whether hooks are
> disabled before assuming your version lacks the feature.

## Interactive vs. non-interactive

`/goal` is offered in two forms that cover different session modes:

- **Interactive terminal (TUI):** the version you invoke by typing `/goal …` in the Claude Code
  prompt.
- **Non-interactive / thin-client (e.g. headless or app-embedded):** a variant that accepts the
  objective as posted text rather than TUI input.

You don't choose between them — Claude Code selects the right one for how you're running. The
behavior (set a condition, work until met) is identical.

## Environment notes

- Some capabilities differ between **local** and **remote** workspaces; if a related feature
  (such as scheduled looping) isn't offered in a remote session, that's expected and separate
  from `/goal` itself.
- Availability may vary with Claude Code's release channel and version, independent of your
  settings.

If everything here checks out and `/goal` still misbehaves, head to
[Troubleshooting](Troubleshooting).
