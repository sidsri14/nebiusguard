# Evidence-based NebiusGuard video

The demo is a narrated evidence replay, not a fabricated live application UI.
The actual authenticated provider output was captured by the main agent on
October 28, 2026. No API key is stored here, and these scripts do not make a
provider call. Synthetic validation cases are labeled throughout the video.

Refresh deterministic evidence with:

```powershell
node demo/capture-evidence.mjs
```

Build the video on this Windows workstation with:

```powershell
uv run --with pillow --with edge-tts python demo/build-video.py
```

The optional media build uses Pillow, Edge neural speech, and FFmpeg/FFprobe;
they are not runtime dependencies of NebiusGuard. Set `FFMPEG_PATH` and
`FFPROBE_PATH` to override the default existing Tracebound media-tool paths.
The renderer uses Windows Segoe UI and Consolas fonts.

Generated frames, narration, working media, and the final MP4 are ignored by
Git. `video-verification.json` records the final duration, codecs and digest;
`nebiusguard-demo.srt` preserves the burned-in caption text and timing.

Do not reuse the captured live result to claim another authenticated run,
model benchmark, quality evaluation, cost saving, hardware measurement or
production deployment.
