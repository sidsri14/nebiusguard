"""Build a narrated evidence replay, not a fabricated live application UI.

Run: uv run --with pillow --with edge-tts python demo/build-video.py
Requires ffmpeg/ffprobe; defaults reuse the installed Tracebound media tooling.
"""
from pathlib import Path
import asyncio
import hashlib
import json
import os
import subprocess
import textwrap

import edge_tts
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / 'demo'
WORK = DEMO / 'work-2026-10-28'
FRAMES = DEMO / 'frames'
FFMPEG = os.environ.get('FFMPEG_PATH', r'D:\distro\tracebound\node_modules\ffmpeg-static\ffmpeg.exe')
FFPROBE = os.environ.get('FFPROBE_PATH', r'D:\distro\tracebound\node_modules\ffprobe-static\bin\win32\x64\ffprobe.exe')
FINAL = DEMO / 'NebiusGuard-Nebius-NVIDIA-Demo.mp4'
EVIDENCE = json.loads((DEMO / 'evidence' / 'verified-evidence.json').read_text())
WIDTH, HEIGHT = 1440, 900
AUDIO_TEMPO = 1.06
BG, PANEL, WHITE, MUTED, GREEN, BLUE = '#07111e', '#101f30', '#f1f6fc', '#9db0c6', '#74edbd', '#70b7ff'
FONTDIR = Path(r'C:\Windows\Fonts')


def font(size, bold=False, mono=False):
    return ImageFont.truetype(str(FONTDIR / ('consola.ttf' if mono else 'segoeuib.ttf' if bold else 'segoeui.ttf')), size)


SCENES = [
    ('A boundary around model-powered tools', 'NEBIUSGUARD', 'Node.js client library + reproducible CLI',
     ['Inspect model input and tool arguments', 'Check streamed output before delivery', 'Keep the evidence inspectable'],
     ['NEBIUS TOKEN FACTORY', 'NVIDIA Nemotron 3 Nano', '', 'Real provider run + synthetic security cases'],
     'NebiusGuard is a small Node.js client library for inspecting model streams and tool arguments. This recording combines a captured real Nebius and NVIDIA run with clearly labeled synthetic security cases. It is a prototype, not a deployed customer service.'),
    ('Where the checks sit', 'ARCHITECTURE', 'No tool execution is hidden inside this library',
     ['Application -> NebiusGuard -> Token Factory', 'Tool arguments -> static approval checks', 'SSE bytes -> pattern checks -> callback'],
     ['Prompt + model + credential identity', '                |', '         bounded HTTPS client', '                |', '     checked stream / hash-linked audit'],
     'The client uses Nebius Token Factory for model discovery and chat completions. Applications call a separate tool-validation boundary. Streamed responses pass through credential-pattern checks before callbacks receive them. The audit log links events with hashes; it is not immutable storage.'),
    ('A real NVIDIA model on Nebius', 'CAPTURED LIVE RUN', 'Authenticated command output - October 28, 2026',
     ['30 account-visible models discovered', 'Selected from the live catalog', 'No private key is displayed or bundled'],
     ['$ npm run demo:live', 'Authenticated model count: 30', '', 'Selected NVIDIA model:', 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B', '', 'Provider: nebius-token-factory'],
     'This is evidence from an actual authenticated run, not a mock response. The client discovered thirty account-visible models and selected NVIDIA Nemotron three Nano, thirty B, A three B. It then streamed an answer through the real Token Factory endpoint. No API key appears in this recording.'),
    ('The returned answer and local audit', 'CAPTURED LIVE RUN', 'Actual output, shortened on screen for readability',
     ['The model explained cloud-metadata SSRF risk', 'Provider path: nebius-token-factory', 'Audit chain verified after the request'],
     ['"Blocking cloud-metadata SSRF calls', 'stops attackers from harvesting', 'sensitive instance credentials..."', '', 'Audit chain valid: true', 'Audit events: 2'],
     'The returned answer explains why cloud-metadata requests can expose instance credentials and create a network pivot. The run reports the Nebius Token Factory provider path, two audit events, and a valid local hash chain. This proves one integration smoke test, not model accuracy or production performance.'),
    ('Private-address representations are blocked', 'SYNTHETIC / OFFLINE', 'These are local validation calls - no target is contacted',
     ['Normalize the hostname before checking it', 'Reject metadata, loopback and private literals', 'Preserve ordinary public HTTPS destinations'],
     ['169.254.169.254  -> ERR_SSRF_DETECTED', '2130706433      -> ERR_SSRF_DETECTED', '10.1.2.3        -> ERR_SSRF_DETECTED', 'LOCALHOST       -> ERR_SSRF_DETECTED', '', 'Network requests made by these cases: 0'],
     'These next cases are synthetic and never contact their targets. URL normalization prevents alternate representations from bypassing the static checks. Metadata, integer-form loopback, private ten-dot addresses, and uppercase localhost are all rejected. DNS resolution and redirects still belong to the executor.'),
    ('A split credential never reaches the callback', 'SYNTHETIC / OFFLINE', 'Pattern-specific regression evidence, not a real secret',
     ['Retain a 39-character suffix while checking', 'Reject a credential split across chunks', 'Flush benign trailing text only after completion'],
     ['Synthetic stream: prefix | remainder', '', 'Result: ERR_CREDENTIAL_LEAK_PREVENTED', 'Emitted credential characters: 0', 'Cache entries after rejection: 0'],
     'A streaming detector cannot recall bytes already delivered. The sanitizer therefore retains a thirty-nine-character suffix, derived from the supported patterns. This synthetic split-credential case rejects before any credential characters reach the callback. Benign withheld text is released only after a complete stream.'),
    ('Incomplete output is not a successful answer', 'SYNTHETIC / OFFLINE', 'Fail-closed completion and account-separated caching',
     ['Missing terminal marker -> reject, do not cache', 'Read JSON incrementally under a byte cap', 'Hash the effective credential into cache identity'],
     ['No terminal [DONE] marker:', '  ERR_NEBIUS_INCOMPLETE_STREAM', '  cache entries: 0', '', 'Same prompt, two synthetic credentials:', '  provider calls: 2; cache entries: 2'],
     'If an SSE response ends without its terminal marker, the client rejects it and creates no successful cache entry. JSON responses are bounded while reading. The cache also separates otherwise identical requests by hashed credential identity, so one account cannot reuse another account\'s inference result.'),
    ('Reproduce the evidence', 'TESTED CODE', 'Fresh local tests and deterministic demonstration',
     ['29 automated tests passed, zero failed', 'Every split point for five credential formats', 'Private IP variants, cancellation and SSE errors'],
     ['$ npm test', 'tests 29', 'pass 29', 'fail 0', '', '$ npm run demo', 'Offline deterministic boundary demo'],
     'The current suite passes all twenty-nine tests. It exercises every split point for five supported credential formats, normalized private addresses, response bounds, cancellation, incomplete streams, in-band errors, and account-separated cache behavior. The public repository includes the deterministic demo and the test commands.'),
    ('Useful checks, explicit limits', 'NEBIUS + NVIDIA', 'One verified provider run. Reproducible boundary tests.',
     ['Static URL checks are not DNS or redirect enforcement', 'Pattern checks cannot detect every attack or secret', 'In-memory audit and cache are prototype components'],
     ['github.com/sidsri14/nebiusguard', '', 'Node.js ESM | zero runtime packages', 'Actual Token Factory streaming proof', 'Synthetic cases are labeled throughout'],
     'NebiusGuard makes these boundaries inspectable without claiming universal security. URL checks do not pin DNS or enforce redirects, pattern checks are incomplete by nature, and the audit and cache remain in memory. The code and captured evidence are public at github dot com slash sidsri fourteen slash nebiusguard.'),
]


def wrapped(draw, text, xy, fnt, color=WHITE, max_width=560, spacing=8):
    x, y = xy
    lines, current = [], ''
    for word in text.split():
        candidate = (current + ' ' + word).strip()
        if draw.textlength(candidate, font=fnt) <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    for line in lines:
        draw.text((x, y), line, font=fnt, fill=color)
        y += fnt.size + spacing
    return y


def render_frames():
    FRAMES.mkdir(parents=True, exist_ok=True)
    for i, (title, badge, subtitle, bullets, terminal, _) in enumerate(SCENES):
        image = Image.new('RGB', (WIDTH, HEIGHT), BG)
        d = ImageDraw.Draw(image)
        d.rectangle((0, 0, WIDTH, 7), fill=GREEN)
        d.text((56, 37), 'NEBIUSGUARD', font=font(24, True), fill=GREEN)
        d.text((1170, 42), f'{i + 1:02d} / {len(SCENES):02d}', font=font(19, mono=True), fill=MUTED)
        d.text((56, 98), title, font=font(43, True), fill=WHITE)
        d.text((58, 160), subtitle, font=font(24), fill=MUTED)
        d.rounded_rectangle((54, 221, 641, 711), 18, fill=PANEL)
        d.rounded_rectangle((672, 221, 1384, 711), 18, fill='#06101b', outline='#2b4057', width=2)
        badge_color = BLUE if 'SYNTHETIC' in badge else GREEN
        d.text((83, 246), badge, font=font(19, True), fill=badge_color)
        y = 308
        for text in bullets:
            d.ellipse((84, y + 13, 92, y + 21), fill=badge_color)
            y = wrapped(d, text, (110, y), font(29), max_width=493, spacing=7) + 26
        d.text((705, 248), 'TERMINAL / EVIDENCE REPLAY', font=font(17, True), fill=MUTED)
        y = 309
        for line in terminal:
            d.text((706, y), line, font=font(24, mono=True), fill=GREEN if line.startswith('$') or 'true' in line else WHITE)
            y += 42
        d.text((57, 753), 'CAPTURED LIVE PROOF + LABELED SYNTHETIC CASES', font=font(17, True), fill=MUTED)
        d.rectangle((54, 790, 1384, 793), fill='#24364b')
        image.save(FRAMES / f'scene-{i + 1:02d}.png')


def run(args):
    subprocess.run([str(x) for x in args], cwd=ROOT, check=True)


def duration(path):
    return float(subprocess.check_output([FFPROBE, '-v', 'error', '-show_entries', 'format=duration', '-of', 'default=nw=1:nk=1', str(path)], text=True))


def srt_time(seconds):
    ms = round(seconds * 1000)
    return f'{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02},{ms % 1000:03}'


async def speech():
    semaphore = asyncio.Semaphore(3)
    async def one(i, scene):
        target = WORK / f'scene-{i + 1:02d}.mp3'
        if target.exists() and target.stat().st_size > 2000:
            return
        async with semaphore:
            await edge_tts.Communicate(scene[-1], 'en-US-AriaNeural', rate='+12%').save(str(target))
    await asyncio.gather(*(one(i, scene) for i, scene in enumerate(SCENES)))


def build():
    if EVIDENCE['tests'] != {'count': 29, 'passed': 29, 'failed': 0}:
        raise RuntimeError('Refresh the scene labels for the current verified test count.')
    WORK.mkdir(parents=True, exist_ok=True)
    render_frames()
    asyncio.run(speech())
    captions, segments, timeline = [], [], 0.0
    for i, scene in enumerate(SCENES):
        audio = WORK / f'scene-{i + 1:02d}.mp3'
        spoken = duration(audio) / AUDIO_TEMPO
        segment_duration = spoken + .5
        segment = WORK / f'scene-{i + 1:02d}.mp4'
        run([FFMPEG, '-y', '-loglevel', 'error', '-loop', '1', '-i', FRAMES / f'scene-{i + 1:02d}.png', '-i', audio,
             '-vf', 'format=yuv420p', '-af', f'atempo={AUDIO_TEMPO},apad=pad_dur=0.5', '-r', '24', '-c:v', 'libx264', '-preset', 'ultrafast', '-crf', '20',
             '-c:a', 'aac', '-b:a', '160k', '-ar', '48000', '-ac', '2', '-t', f'{segment_duration:.3f}', '-movflags', '+faststart', segment])
        words = scene[-1].split()
        chunks = [' '.join(words[x:x + 11]) for x in range(0, len(words), 11)]
        offset = 0
        for chunk in chunks:
            end = offset + len(chunk.split())
            captions.append(f'{len(captions) + 1}\n{srt_time(timeline + spoken * offset / len(words))} --> {srt_time(timeline + spoken * end / len(words))}\n{chunk}')
            offset = end
        timeline += segment_duration
        segments.append(segment)
        print(f'Built scene {i + 1}/{len(SCENES)}: {segment_duration:.2f}s', flush=True)
    if timeline > 170:
        raise RuntimeError(f'Video would be {timeline:.1f}s; shorten narration before delivery.')
    srt = DEMO / 'nebiusguard-demo.srt'
    srt.write_text('\n\n'.join(captions) + '\n', encoding='utf8')
    concat = WORK / 'segments.ffconcat'
    concat.write_text('ffconcat version 1.0\n' + '\n'.join(f"file '{p.as_posix()}'" for p in segments), encoding='utf8')
    joined = WORK / 'joined.mp4'
    run([FFMPEG, '-y', '-loglevel', 'error', '-safe', '0', '-f', 'concat', '-i', concat, '-c', 'copy', joined])
    run([FFMPEG, '-y', '-loglevel', 'error', '-i', joined,
         '-vf', "subtitles=demo/nebiusguard-demo.srt:force_style='FontName=Segoe UI,FontSize=12,PrimaryColour=&H00FFFFFF,OutlineColour=&H0007111E,BorderStyle=3,BackColour=&HC007111E,Outline=1,Shadow=0,Alignment=2,MarginL=70,MarginR=70,MarginV=15'",
         '-af', 'loudnorm=I=-16:TP=-1.5:LRA=11', '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '19', '-pix_fmt', 'yuv420p',
         '-c:a', 'aac', '-b:a', '160k', '-ar', '48000', '-ac', '2', '-movflags', '+faststart', FINAL])
    probe = json.loads(subprocess.check_output([FFPROBE, '-v', 'error', '-show_streams', '-show_format', '-of', 'json', FINAL], text=True))
    report = {'path': str(FINAL), 'duration': float(probe['format']['duration']), 'bytes': FINAL.stat().st_size,
              'sha256': hashlib.sha256(FINAL.read_bytes()).hexdigest(),
              'streams': [{k: stream.get(k) for k in ['codec_type', 'codec_name', 'width', 'height', 'sample_rate', 'channels']} for stream in probe['streams']],
              'voice': 'en-US-AriaNeural', 'captions': len(captions), 'scenes': len(SCENES)}
    (DEMO / 'video-verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    build()
