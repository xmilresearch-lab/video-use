# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**video-use** is a conversation-driven video editing skill for AI coding assistants (Claude Code, Codex, Hermes, etc.). Drop raw footage in a folder, chat with Claude Code, get `final.mp4` back. It works by reading transcripts and generating editing decisions — the LLM never watches the video raw.

- **Language**: Python 3.10+ (helpers), with optional Node.js for HyperFrames/Remotion animation slots
- **License**: MIT
- **Core dependency**: ElevenLabs Scribe API (`ELEVENLABS_API_KEY`)

## Repository Layout

```
video-use/
  SKILL.md                  # Full production rules, editing craft, animation specs (daily use)
  install.md                # First-time setup instructions (run once)
  pyproject.toml            # Python project metadata + dependencies
  .env.example              # Template for ELEVENLABS_API_KEY
  helpers/
    transcribe.py           # Single-file Scribe transcription (word-level, cached)
    transcribe_batch.py     # 4-worker parallel transcription of a directory
    pack_transcripts.py     # transcripts/*.json → takes_packed.md (phrase-level view)
    timeline_view.py        # Filmstrip + waveform PNG for a time range (on-demand only)
    render.py               # EDL → per-segment extract → concat → overlays → subtitles
    grade.py                # Per-segment ffmpeg color grade
  skills/
    manim-video/            # Vendored Manim animation sub-skill
      SKILL.md              # Manim-specific instructions
      references/           # Manim reference docs
      scripts/              # Manim helper scripts
  static/
    timeline-view.svg       # Diagram used in README
    video-use-banner.png    # README banner
  poster.html               # Project poster
```

## Session Output Layout

All session outputs go into `<videos_dir>/edit/` — never inside the `video-use/` project directory.

```
<videos_dir>/
  <source files — untouched>
  edit/
    project.md              # Session memory — append each session, read on startup
    takes_packed.md         # Phrase-level transcript (primary LLM reading view)
    edl.json                # Cut decisions
    transcripts/<name>.json # Cached raw Scribe JSON (immutable — never re-transcribe)
    animations/slot_<id>/   # Per-animation source, render, and reasoning
    clips_graded/           # Per-segment extracts with grade + fades
    master.srt              # Output-timeline subtitles
    downloads/              # yt-dlp outputs
    verify/                 # Debug frames / timeline PNGs
    preview.mp4
    final.mp4
```

## Setup

**First time only** — follow `install.md`. The steps are:
1. Clone to a stable path (e.g., `~/Developer/video-use`).
2. Install Python deps: `uv sync` or `pip install -e .`
3. Install `ffmpeg` (hard requirement) and optionally `yt-dlp`.
4. Symlink into the agent's skills directory (`~/.claude/skills/video-use`).
5. Set `ELEVENLABS_API_KEY` in `.env` at the repo root.

**On every cold start**, verify: `ELEVENLABS_API_KEY` is set, `ffmpeg`/`ffprobe` are on PATH, Python deps are installed.

## Python Dependencies

From `pyproject.toml` — no external build tools needed for normal use:

```
requests, librosa, matplotlib, pillow, numpy
```

Optional (for animations): `manim` (`pip install -e ".[animations]"`)

Node.js 22+ and npm are only needed for HyperFrames or Remotion animation slots — install lazily on first use, never globally.

## Helper Scripts

All helpers are invoked directly as `python helpers/<name>.py` (no console scripts):

| Helper | Purpose |
|---|---|
| `transcribe.py <video>` | Single-file word-level Scribe call; cached per source |
| `transcribe_batch.py <dir>` | 4-worker parallel transcription of a footage directory |
| `pack_transcripts.py --edit-dir <dir>` | Pack `transcripts/*.json` → `takes_packed.md` |
| `timeline_view.py <video> <start> <end>` | Filmstrip + waveform PNG — use at decision points only |
| `render.py <edl.json> -o <out>` | Full render pipeline: extract → concat → overlays → subtitles |
| `grade.py <in> -o <out>` | Apply ffmpeg color grade; `--list-presets` to list options |

Resolve helper paths relative to the directory containing `SKILL.md` (typically `~/.claude/skills/video-use/helpers/`).

## Hard Production Rules (Non-Negotiable)

These prevent silent failures in rendered output:

1. **Subtitles LAST** — applied after every overlay in the filter chain.
2. **Per-segment extract → lossless concat** — never single-pass filtergraph with overlays.
3. **30ms audio fades at every segment boundary** — prevents audible pops.
4. **Overlays use `setpts=PTS-STARTPTS+T/TB`** — shifts overlay frame 0 to window start.
5. **Master SRT uses output-timeline offsets**: `output_time = word.start - segment_start + segment_offset`.
6. **Never cut inside a word** — snap every cut edge to a word boundary.
7. **Pad every cut edge** — 30–200ms working window; Scribe timestamps drift 50–100ms.
8. **Word-level verbatim ASR only** — never SRT/phrase mode; never normalized fillers.
9. **Cache transcripts per source** — never re-transcribe unless the source file changed.
10. **Parallel sub-agents for multiple animations** — spawn N at once via the Agent tool.
11. **Strategy confirmation before execution** — never touch the cut without user approval.
12. **All session outputs in `<videos_dir>/edit/`** — never write inside the `video-use/` repo.

## Animation Engines

Pick per-slot — do not default to one engine for everything:

| Engine | Best for |
|---|---|
| **HyperFrames** | HTML/CSS/GSAP compositions, product UI motion, kinetic typography, transparent WebM overlays |
| **Remotion** | React/CSS compositions, reusable React primitives, existing Remotion brand systems |
| **Manim** | Formal diagrams, state machines, equation derivations, graph morphs (see `skills/manim-video/SKILL.md`) |
| **PIL + PNG + ffmpeg** | Simple overlay cards: counters, typewriter text, bar reveals |

HyperFrames: scaffold in `edit/animations/slot_<id>/` with `npx --yes hyperframes init . --example blank --non-interactive --skip-skills`, then render with `npx --yes hyperframes render . -o render.mp4`.

Remotion: scaffold with `npx create-video@latest` inside the slot directory; render with the project-local `remotion render` command.

## Development Conventions

- `SKILL.md` is the authoritative daily-use reference for the AI assistant — read it at the start of every editing session.
- `install.md` is for first-time setup only — do not re-run every session.
- Helpers are scripts, not a library — call them via `python helpers/<name>.py`, not by importing.
- Never import helpers across animation slots — each slot is self-contained.
- Animation sub-agents are spawned via the `Agent` tool with fully self-contained prompts (no parent context is inherited).
- All EDL output is JSON (`edl.json`) — see `SKILL.md` for the schema.
- Cap self-eval render passes at **3** — if issues remain after 3 passes, flag to the user.

## Git Workflow

- Default branch: `main`
- No automated CI currently configured
- Never commit `.env` (contains the ElevenLabs API key)
- `git pull --ff-only` to update; re-run `uv sync` / `pip install -e .` if `pyproject.toml` changed
