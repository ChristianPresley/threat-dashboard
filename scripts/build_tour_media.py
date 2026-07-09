#!/usr/bin/env python3
"""Assemble guided-tour media from captured PNG frames.

Reads the numbered PNG strips written by `threat-dashboard --tour <dir>` and
produces, in the wiki images directory:
  - one animated GIF per GIF scene (downscaled + quantized, readable)
  - one JPG still per still scene (last settled frame)

Usage: python scripts/build_tour_media.py <tour_dir> <wiki_images_dir>
"""
import sys, os, glob, re
from PIL import Image

# Scene name -> ("gif", frame_ms) or ("still", None). Kept in sync with
# Dashboard.tour_scenes.
SCENES = {
    "01-triage":         ("still", None),
    "02-alert-select":   ("still", None),
    "03-hunt":           ("still", None),
    "04-timeline-brush": ("gif", 110),
    "05-process-tree":   ("still", None),
    "06-detect":         ("still", None),
    "07-yara-detail":    ("still", None),
    "08-yara-ci":        ("gif", 130),
    "09-attack-drill":   ("still", None),
    "10-intel":          ("still", None),
    "11-enrich-job":     ("gif", 130),
    "12-enrich-detail":  ("still", None),
    "13-pivot":          ("gif", 320),
    "14-ops":            ("still", None),
    "15-ai-config":      ("still", None),
    "16-ai-chat":        ("gif", 260),
    "17-settings":       ("still", None),
    "18-theme-tour":     ("gif", 700),
    "19-ir-triage":      ("gif", 400),
    "20-ir-scope":       ("gif", 300),
    "21-ir-chain":       ("still", None),
    "22-ir-verdict":     ("gif", 200),
    "23-ir-contain":     ("gif", 350),
}

GIF_WIDTH = 1120   # downscale for a readable-but-compact GIF
JPG_WIDTH = 1400   # stills keep full resolution


def frames(tour_dir, scene):
    fs = sorted(glob.glob(os.path.join(tour_dir, f"{scene}-*.png")),
                key=lambda p: int(re.search(r"-(\d+)\.png$", p).group(1)))
    return fs


def make_gif(tour_dir, scene, ms, out_path):
    fs = frames(tour_dir, scene)
    if not fs:
        print(f"  !! no frames for {scene}")
        return
    imgs = []
    for f in fs:
        im = Image.open(f).convert("RGB")
        if im.width != GIF_WIDTH:
            h = round(im.height * GIF_WIDTH / im.width)
            im = im.resize((GIF_WIDTH, h), Image.LANCZOS)
        # Adaptive palette per frame keeps the dark UI + accent colors crisp.
        imgs.append(im.quantize(colors=128, method=Image.FASTOCTREE, dither=Image.NONE))
    # Hold the final frame ~5x so the result is legible before the loop.
    durations = [ms] * (len(imgs) - 1) + [ms * 5]
    imgs[0].save(out_path, save_all=True, append_images=imgs[1:],
                 duration=durations, loop=0, optimize=True, disposal=2)
    print(f"  gif  {os.path.basename(out_path)}  ({len(imgs)} frames, {os.path.getsize(out_path)//1024} KB)")


def make_still(tour_dir, scene, out_path):
    fs = frames(tour_dir, scene)
    if not fs:
        print(f"  !! no frames for {scene}")
        return
    im = Image.open(fs[-1]).convert("RGB")
    if im.width != JPG_WIDTH:
        h = round(im.height * JPG_WIDTH / im.width)
        im = im.resize((JPG_WIDTH, h), Image.LANCZOS)
    im.save(out_path, "JPEG", quality=88, optimize=True)
    print(f"  jpg  {os.path.basename(out_path)}  ({os.path.getsize(out_path)//1024} KB)")


def main():
    tour_dir, img_dir = sys.argv[1], sys.argv[2]
    os.makedirs(img_dir, exist_ok=True)
    for scene, (kind, ms) in SCENES.items():
        if kind == "gif":
            make_gif(tour_dir, scene, ms, os.path.join(img_dir, f"tour-{scene}.gif"))
        else:
            make_still(tour_dir, scene, os.path.join(img_dir, f"tour-{scene}.jpg"))


if __name__ == "__main__":
    main()
