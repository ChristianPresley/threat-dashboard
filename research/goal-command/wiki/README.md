# `/goal` command guide — wiki source

This folder is the **source of truth** for the behavior-level guide to Claude Code's `/goal`
command that is published to this repository's GitHub wiki. The pages are plain Markdown in
GitHub-wiki format (`Home.md` is the entry point; `_Sidebar.md` / `_Footer.md` are
wiki-global; page links use the file name without `.md`).

**Scope.** This guide documents only the **observable behavior** of `/goal` and the
**publicly documented** Claude Code hooks mechanics it builds on. It deliberately contains no
proprietary implementation detail — see `Methodology-and-Scope.md` for the exact boundary and
the reasons for it. It is a research addendum and is unrelated to the threat-dashboard
application itself.

**Publishing.** See `PUBLISHING.md` for how these pages map onto the GitHub wiki.

## Pages

| File | Page |
|---|---|
| `Home.md` | Landing page & navigation |
| `Overview.md` | What `/goal` is; when to use it |
| `Usage.md` | Syntax, sub-commands, examples |
| `How-It-Works.md` | The check-after-each-turn model (public hooks mechanics) |
| `Requirements-and-Availability.md` | Preconditions: version, trust, hooks |
| `goal-vs-loop.md` | `/goal` (persist to a condition) vs `/loop` (poll on a schedule) |
| `Troubleshooting.md` | Common issues and fixes |
| `Methodology-and-Scope.md` | How this was written; what's intentionally excluded |
| `Bibliography.md` | Sources and further reading |
