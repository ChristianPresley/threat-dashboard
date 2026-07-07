# Vendored fonts

Fonts used by the dashboard renderer and the MSDF library tests.

## Hack-Regular.ttf

- **Source**: https://github.com/source-foundry/Hack release v3.003,
  file `Hack-v3.003-ttf.zip` → `ttf/Hack-Regular.ttf`.
- **License**: Modified Bitstream Vera and Bitstream Charter licenses,
  redistributable. Hack is MIT-compatible. See the upstream `LICENSE.md`
  in the release archive.
- **Why this font**: ships a clean `glyf` table (TrueType, not CFF/OTF),
  full ASCII printable coverage, ~300 KB. The MSDF tests
  (`tests/test_ttf.zig`, `tests/test_contour.zig`) load it at runtime via
  `std.fs.cwd().openFile` and **gracefully skip** with `error.SkipZigTest`
  if the file is missing — so a fresh clone passes `zig build test` even
  before this asset is vendored.
- **Why not Geist (the dashboard's UI font)**: Geist is earmarked for PR 3
  (final dashboard wiring). Keeping the bake fixtures on a separate font
  isolates parser-correctness regressions from font-specific quirks.

## Vendoring procedure

```powershell
# From repo root:
Invoke-WebRequest -Uri "https://github.com/source-foundry/Hack/releases/download/v3.003/Hack-v3.003-ttf.zip" -OutFile "$env:TEMP\hack.zip"
Expand-Archive -Path "$env:TEMP\hack.zip" -DestinationPath "$env:TEMP\hack" -Force
Copy-Item "$env:TEMP\hack\ttf\Hack-Regular.ttf" "assets\fonts\Hack-Regular.ttf"
```

After vendoring, run `zig build test` — the `test_ttf` and `test_contour`
test blocks will now exercise the parser against a real font.
