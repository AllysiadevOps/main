#!/usr/bin/env python3
"""Generate bounded, deterministic synthetic MP4 media for local workflows.

The generator has no input-media option and never reads user media. Output is
reproducible byte-for-byte when run with the same arguments and pinned FFmpeg
build; FFmpeg/encoder version changes may change the encoded bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_DIMENSION = 1280
MAX_DURATION_SECONDS = 10
MAX_FPS = 30
MAX_SEED = (1 << 32) - 1
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
PROCESS_TIMEOUT_SECONDS = 60
AUDIO_MODES = ("none", "sine", "noise")


class GeneratorError(RuntimeError):
    """A stable, privacy-safe generation failure."""


def validate_options(
    output: Path,
    width: int,
    height: int,
    duration: int,
    fps: int,
    seed: int,
    audio: str = "none",
) -> None:
    if output.suffix.lower() != ".mp4":
        raise GeneratorError("output must use the .mp4 extension")
    if width < 16 or width > MAX_DIMENSION or width % 2:
        raise GeneratorError(f"width must be even and between 16 and {MAX_DIMENSION}")
    if height < 16 or height > MAX_DIMENSION or height % 2:
        raise GeneratorError(f"height must be even and between 16 and {MAX_DIMENSION}")
    if duration < 1 or duration > MAX_DURATION_SECONDS:
        raise GeneratorError(f"duration must be between 1 and {MAX_DURATION_SECONDS} seconds")
    if fps < 1 or fps > MAX_FPS:
        raise GeneratorError(f"fps must be between 1 and {MAX_FPS}")
    if seed < 0 or seed > MAX_SEED:
        raise GeneratorError(f"seed must be between 0 and {MAX_SEED}")
    if audio not in AUDIO_MODES:
        raise GeneratorError("audio must be one of: none, sine, noise")


def build_command(
    ffmpeg: str,
    output: Path,
    width: int,
    height: int,
    duration: int,
    fps: int,
    seed: int,
    audio: str = "none",
) -> list[str]:
    if audio not in AUDIO_MODES:
        raise GeneratorError("audio must be one of: none, sine, noise")
    source = f"testsrc2=size={width}x{height}:rate={fps},noise=alls=10:all_seed={seed}"
    if audio == "none":
        return [
            ffmpeg,
            "-nostdin",
            "-hide_banner",
            "-loglevel", "error",
            "-y",
            "-f", "lavfi",
            "-i", source,
            "-t", str(duration),
            "-map_metadata", "-1",
            "-metadata", "creation_time=1970-01-01T00:00:00Z",
            "-an",
            "-c:v", "libx264",
            "-preset", "medium",
            "-crf", "23",
            "-pix_fmt", "yuv420p",
            "-threads", "1",
            "-fflags", "+bitexact",
            "-flags:v", "+bitexact",
            "-movflags", "+faststart",
            str(output),
        ]

    if audio == "sine":
        audio_source = f"sine=frequency={220 + (seed % 660)}:sample_rate=44100"
    else:
        audio_source = f"anoisesrc=color=white:sample_rate=44100:amplitude=0.1:seed={seed}"

    return [
        ffmpeg,
        "-nostdin",
        "-hide_banner",
        "-loglevel", "error",
        "-y",
        "-f", "lavfi",
        "-i", source,
        "-f", "lavfi",
        "-i", audio_source,
        "-t", str(duration),
        "-map_metadata", "-1",
        "-metadata", "creation_time=1970-01-01T00:00:00Z",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "23",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "64k",
        "-ar", "44100",
        "-ac", "1",
        "-threads", "1",
        "-fflags", "+bitexact",
        "-flags:v", "+bitexact",
        "-flags:a", "+bitexact",
        "-movflags", "+faststart",
        str(output),
    ]


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as media:
        for chunk in iter(lambda: media.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate(
    output: Path,
    *,
    width: int = 320,
    height: int = 240,
    duration: int = 3,
    fps: int = 30,
    seed: int = 0,
    audio: str = "none",
    force: bool = False,
    ffmpeg: str = "ffmpeg",
) -> tuple[int, str]:
    validate_options(output, width, height, duration, fps, seed, audio)
    output = output.expanduser()
    if not output.parent.is_dir():
        raise GeneratorError("output directory does not exist")
    if output.exists() and not force:
        raise GeneratorError("output already exists; pass --force to replace it")
    if output.is_dir():
        raise GeneratorError("output must be a file path")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".harpocrates-synthetic-", suffix=".mp4", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        try:
            subprocess.run(
                build_command(ffmpeg, temporary, width, height, duration, fps, seed, audio),
                check=True,
                capture_output=True,
                timeout=PROCESS_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as exc:
            raise GeneratorError("dependency_failure: ffmpeg is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise GeneratorError("dependency_failure: ffmpeg exceeded the generation time limit") from exc
        except subprocess.CalledProcessError as exc:
            raise GeneratorError("dependency_failure: ffmpeg could not generate synthetic media") from exc

        size = temporary.stat().st_size
        if size == 0:
            raise GeneratorError("dependency_failure: ffmpeg produced empty output")
        if size > MAX_OUTPUT_BYTES:
            raise GeneratorError("generated media exceeds the 64 MiB output limit")

        try:
            if force:
                os.replace(temporary, output)
            else:
                os.link(temporary, output)
                temporary.unlink()
        except FileExistsError as exc:
            raise GeneratorError("output already exists; pass --force to replace it") from exc
        return size, _digest(output)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Destination .mp4 path")
    parser.add_argument("--width", type=int, default=320, help="Even frame width (16-1280)")
    parser.add_argument("--height", type=int, default=240, help="Even frame height (16-1280)")
    parser.add_argument("--duration", type=int, default=3, help="Duration in seconds (1-10)")
    parser.add_argument("--fps", type=int, default=30, help="Frame rate (1-30)")
    parser.add_argument("--seed", type=int, default=0, help="Noise seed (0-4294967295)")
    parser.add_argument(
        "--audio",
        default="none",
        help="Deterministic audio stream mode (sine, noise, none)",
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing output file")
    args = parser.parse_args(argv)

    try:
        size, digest = generate(
            args.output,
            width=args.width,
            height=args.height,
            duration=args.duration,
            fps=args.fps,
            seed=args.seed,
            audio=args.audio,
            force=args.force,
        )
    except GeneratorError as exc:
        print(f"synthetic_media: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"synthetic_media: filesystem failure ({type(exc).__name__})", file=sys.stderr)
        return 1

    print(f"generated synthetic MP4: {size} bytes sha256={digest} audio={args.audio}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())