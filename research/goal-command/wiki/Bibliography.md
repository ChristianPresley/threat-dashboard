# Bibliography

Sources relied on for this wiki, and further reading. Entries are grouped by type. Access date
for all URLs: **July 2026**. Where the official documentation and any third-party source
disagree, treat the official documentation as authoritative.

## Primary sources — official Claude Code documentation

1. **Claude Code — Overview.** Anthropic / Claude Docs.
   <https://docs.claude.com/en/docs/claude-code/overview>
   *The product this wiki is about; general capabilities and concepts.*

2. **Slash commands.** Claude Code Docs.
   <https://docs.claude.com/en/docs/claude-code/slash-commands>
   *How slash commands (including built-ins and custom `/name` commands) work and where they
   live. Basis for the command-surface description in [Usage](Usage).*

3. **Hooks — Get started / Hooks guide.** Claude Code Docs.
   <https://docs.claude.com/en/docs/claude-code/hooks-guide>
   *Introduction to the hooks system that `/goal` is built on.*

4. **Hooks reference.** Claude Code Docs.
   <https://code.claude.com/docs/en/hooks>
   *Authoritative reference for hook events, the **Stop hook**, blocking vs. non-blocking
   behavior, the `stop_hook_active` flag, and the consecutive-block safety cap. This is the
   backbone of [How It Works](How-It-Works).*

5. **CLI reference.** Claude Code Docs.
   <https://docs.claude.com/en/docs/claude-code/cli-reference>
   *Interactive vs. non-interactive invocation, referenced in
   [Requirements & Availability](Requirements-and-Availability).*

6. **Slash commands in the SDK.** Claude Agent SDK Docs.
   <https://docs.claude.com/en/docs/claude-code/sdk/sdk-slash-commands>
   *How slash commands are dispatched programmatically; context for the non-interactive form of
   `/goal`.*

## Secondary sources — community guides on hooks (further reading)

These are third-party explanations of Claude Code's Stop-hook behavior. They corroborate the
public mechanics summarized here but are not authoritative; verify against the official
[hooks reference](https://code.claude.com/docs/en/hooks).

7. **"Stop Hook."** Developers Digest.
   <https://www.developersdigest.tech/guides/stop-hook>

8. **"How Claude Code stop hooks work."** Amit Kothari.
   <https://amitkoth.com/claude-code-stop-hooks/>

9. **"Claude Code Hooks: A Practical Guide to Workflow Automation."** DataCamp.
   <https://www.datacamp.com/tutorial/claude-code-hooks>

10. **"Claude Code Stop Hook: Force Task Completion."** claudefa.st.
    <https://claudefa.st/blog/tools/hooks/stop-hook-task-enforcement>

## Tooling & platform references

11. **About wikis / Adding or editing wiki pages.** GitHub Docs.
    <https://docs.github.com/en/communities/documenting-your-project-with-wikis/about-wikis>
    *Wiki page format, the `Home` landing page, and `_Sidebar` / `_Footer` conventions used by
    this wiki.*

12. **Node.js.** OpenJS Foundation.
    <https://nodejs.org/>
    *Runtime for the behavioral reference model kept in the local research module.*

## Primary internal source

13. **`research/goal-command/` — local research module.** This repository.
    *The behavioral observations summarized in this wiki. The module's deeper technical notes
    are intentionally **not** reproduced here; see [Methodology & Scope](Methodology-and-Scope)
    for the boundary and the reasons for it.*

---

## Citation notes

- **Behavioral claims** (sub-commands, outcomes, refusal conditions, `/goal` vs `/loop`) derive
  from direct observation of the feature, cross-checked against sources 2–5.
- **Mechanism claims** ("built on Stop hooks," "blocks the stop to continue," "a cap prevents
  infinite loops") derive from the public hooks documentation, sources 3–4.
- **No proprietary internals** — verbatim prompts, internal identifiers, flag names, or
  extracted source — are cited or reproduced, by design. See
  [Methodology & Scope](Methodology-and-Scope).
