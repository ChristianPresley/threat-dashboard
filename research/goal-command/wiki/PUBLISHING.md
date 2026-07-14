# Publishing these pages to the GitHub wiki

These files are staged in `research/goal-command/wiki/` and follow GitHub's wiki conventions
(`Home.md` is the landing page; `_Sidebar.md` and `_Footer.md` are auto-included on every page;
page links use the file name without `.md`).

> **One-time prerequisite:** the wiki must be enabled and initialized. In the repo on GitHub,
> open the **Wiki** tab and create the first page once (any content) — this creates the
> `*.wiki.git` remote. After that you can push to it.

## Publish with git

```bash
# from a scratch location, not inside the main repo
git clone https://github.com/ChristianPresley/threat-dashboard.wiki.git
cd threat-dashboard.wiki

# copy the staged pages in
cp /path/to/threat-dashboard/research/goal-command/wiki/*.md .

git add .
git commit -m "docs(wiki): behavior-level guide to the /goal command"
git push origin master   # GitHub wikis use the 'master' branch
```

## Notes

- GitHub renders `_Sidebar.md` and `_Footer.md` specially; keep those names.
- Editing on github.com (the Wiki tab's web editor) works too — paste each page's contents.
- This is the **publication-safe** set: observable behavior + public hooks mechanics only, no
  proprietary internals. See `Methodology-and-Scope.md`.
