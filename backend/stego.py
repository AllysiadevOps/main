from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import struct
import subprocess
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from tracing import traced

import numpy as np

from envelope import (
    MAGIC_V1,
    MAGIC_V2,
    MAX_PAYLOAD_BYTES,
    pack_envelope,
    unpack_envelope,
    canonical_metadata_hash,
)

BORDER_BLOCK = 6
BORDER_STRIDE = 2


@dataclass(frozen=True)
class VideoInfo:
    width: int
    height: int
    fps: str
    frame_count: int | None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_metadata_hash_compat(metadata: dict[str, Any]) -> str:
    return canonical_metadata_hash(metadata)


@traced("media.embed", attributes={"media.operation": "embed"})
def embed_metadata(
    source_path: Path | str,
    output_path: Path | str,
    metadata: dict[str, Any],
    progress_callback: Callable[[int, int | None], None] | None = None,
) -> None:
    """Embed ``metadata`` into the video.

    ``progress_callback(frames_done, frames_total)`` is called after each frame is
    written; ``frames_total`` is ``None`` when ffprobe cannot report a frame count.
    """
    ffmpeg = _require("ffmpeg")
    info = _probe_video(source_path)
    payload = pack_envelope(metadata)
    bits = _bytes_to_bits(payload)

    border_capacity = _border_capacity(info.width, info.height) * (info.frame_count or 1)
    lsb_capacity = info.width * info.height * 3 * (info.frame_count or 1)
    if len(bits) > border_capacity and len(bits) > lsb_capacity:
        raise ValueError("metadata payload is larger than the available video steganography capacity")

    process_in = _start_decode(ffmpeg, source_path, info)
    process_out = _start_encode(ffmpeg, output_path, info)
    timer_in = _kill_after_timeout(process_in, 60.0)
    timer_out = _kill_after_timeout(process_out, 60.0)
    frame_size = info.width * info.height * 3
    bit_cursor = 0
    frames_done = 0

    try:
        while True:
            raw = process_in.stdout.read(frame_size)
            if not raw:
                break
            if len(raw) != frame_size:
                raise RuntimeError("ffmpeg returned a partial frame")

            frame = np.frombuffer(raw, dtype=np.uint8).copy().reshape((info.height, info.width, 3))
            bit_cursor = _embed_border_bits(frame, bits, bit_cursor)
            _embed_lsb_bits(frame, bits)
            process_out.stdin.write(frame.tobytes())
            frames_done += 1
            if progress_callback is not None:
                progress_callback(frames_done, info.frame_count)

        process_out.stdin.close()
        decode_status = process_in.wait(timeout=30)
        encode_status = process_out.wait(timeout=30)
        if decode_status != 0:
            raise RuntimeError("ffmpeg failed while decoding the source video")
        if encode_status != 0:
            raise RuntimeError("ffmpeg failed while encoding the steganographic video")
    finally:
        timer_in.cancel()
        timer_out.cancel()
        _close_process(process_in)
        _close_process(process_out)


@traced("media.extract", attributes={"media.operation": "extract"})
def extract_metadata(source_path: Path | str) -> dict[str, Any] | None:
    ffmpeg = _require("ffmpeg")
    info = _probe_video(source_path)
    process = _start_decode(ffmpeg, source_path, info)
    timer = _kill_after_timeout(process, 60.0)
    frame_size = info.width * info.height * 3
    frames: list[np.ndarray] = []

    try:
        for _ in range(info.frame_count or 240):
            raw = process.stdout.read(frame_size)
            if not raw:
                break
            if len(raw) != frame_size:
                break
            frames.append(np.frombuffer(raw, dtype=np.uint8).reshape((info.height, info.width, 3)).copy())
            border_value = _extract_from_border(frames, info.width, info.height)
            if border_value is not None:
                return border_value

        return _extract_from_lsb(frames)
    finally:
        timer.cancel()
        _close_process(process)


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for index in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _border_positions(width: int, height: int) -> list[tuple[int, int]]:
    positions: list[tuple[int, int]] = []
    for x in range(0, width, BORDER_BLOCK):
        positions.append((BORDER_STRIDE, x))
    for y in range(BORDER_BLOCK, height, BORDER_BLOCK):
        positions.append((y, width - BORDER_STRIDE - 1))
    for x in range(width - BORDER_BLOCK, -1, -BORDER_BLOCK):
        positions.append((height - BORDER_STRIDE - 1, x))
    for y in range(height - BORDER_BLOCK, BORDER_BLOCK - 1, -BORDER_BLOCK):
        positions.append((y, BORDER_STRIDE))
    return positions


def _border_capacity(width: int, height: int) -> int:
    return len(_border_positions(width, height))


def _embed_border_bits(frame: np.ndarray, bits: list[int], cursor: int) -> int:
    height, width, _ = frame.shape
    for y, x in _border_positions(width, height):
        if cursor >= len(bits):
            break
        bit = bits[cursor]
        color = 238 if bit else 17
        y0 = max(0, y - BORDER_STRIDE)
        y1 = min(height, y + BORDER_STRIDE + 1)
        x0 = max(0, x - BORDER_STRIDE)
        x1 = min(width, x + BORDER_STRIDE + 1)
        frame[y0:y1, x0:x1, :] = color
        cursor += 1
    return cursor


def _embed_lsb_bits(frame: np.ndarray, bits: list[int]) -> None:
    flat = frame.reshape(-1)
    limit = min(len(bits), len(flat))
    if limit == 0:
        return
    bit_values = np.asarray(bits[:limit], dtype=np.uint8)
    flat[:limit] = (flat[:limit] & np.uint8(0xFE)) | bit_values


def _extract_from_border(frames: list[np.ndarray], width: int, height: int) -> dict[str, Any] | None:
    bits: list[int] = []
    for frame in frames:
        for y, x in _border_positions(width, height):
            y0 = max(0, y - BORDER_STRIDE)
            y1 = min(height, y + BORDER_STRIDE + 1)
            x0 = max(0, x - BORDER_STRIDE)
            x1 = min(width, x + BORDER_STRIDE + 1)
            bits.append(1 if int(frame[y0:y1, x0:x1, :].mean()) >= 128 else 0)

    return _unpack_progressive(bits)


def _extract_from_lsb(frames: list[np.ndarray]) -> dict[str, Any] | None:
    bits: list[int] = []
    for frame in frames:
        bits.extend(int(value & 1) for value in frame.reshape(-1))
        value = _unpack_progressive(bits)
        if value is not None:
            return value
    return None


def _unpack_progressive(bits: list[int]) -> dict[str, Any] | None:
    header_bits = (7 + 4 + 32) * 8
    if len(bits) < header_bits:
        return None

    header = _bits_to_bytes(bits[:header_bits])
    magic = header[:7]
    if magic not in (MAGIC_V1, MAGIC_V2):
        return None

    size = struct.unpack(">I", header[7:11])[0]
    if size > MAX_PAYLOAD_BYTES:
        return None

    total_bits = (7 + 4 + 32 + size) * 8
    if len(bits) < total_bits:
        return None

    return unpack_envelope(_bits_to_bytes(bits[:total_bits]))


def _probe_video(path: Path | str) -> VideoInfo:
    ffprobe = _require("ffprobe")
    try:
        result = subprocess.run(
            [
                ffprobe,
                "-v",
                "error",
                "-probesize",
                "5000000",
                "-analyzeduration",
                "5000000",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=width,height,r_frame_rate,nb_frames",
                "-of",
                "json",
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise RuntimeError("ffprobe failed to parse the video file")
    
    try:
        streams = json.loads(result.stdout).get("streams", [])
    except json.JSONDecodeError:
        raise RuntimeError("ffprobe returned invalid json")
        
    if not streams:
        raise ValueError("uploaded file does not contain a video stream")

    stream = streams[0]
    frames = stream.get("nb_frames")
    return VideoInfo(
        width=int(stream["width"]),
        height=int(stream["height"]),
        fps=stream.get("r_frame_rate") or "30/1",
        frame_count=int(frames) if str(frames).isdecimal() else None,
    )


def _start_decode(ffmpeg: str, source_path: Path | str, info: VideoInfo) -> subprocess.Popen[bytes]:
    kwargs: dict[str, Any] = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True
    return subprocess.Popen(
        [
            ffmpeg,
            "-v",
            "error",
            "-i",
            str(source_path),
            "-map",
            "0:v:0",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


def _start_encode(ffmpeg: str, output_path: Path | str, info: VideoInfo) -> subprocess.Popen[bytes]:
    kwargs: dict[str, Any] = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True
    return subprocess.Popen(
        [
            ffmpeg,
            "-y",
            "-v",
            "error",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-s",
            f"{info.width}x{info.height}",
            "-r",
            info.fps,
            "-i",
            "-",
            "-an",
            "-c:v",
            "libx264",
            "-preset",
            "medium",
            "-crf",
            "16",
            "-pix_fmt",
            "yuv420p",
            str(output_path),
        ],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


def _require(binary: str) -> str:
    found = shutil.which(binary)
    if not found:
        raise RuntimeError(f"{binary} is required for steganography processing")
    return found


def _kill_after_timeout(
    process: subprocess.Popen[bytes],
    timeout_seconds: float,
) -> threading.Timer:
    def kill_process() -> None:
        if process.poll() is not None:
            return
        if os.name != "nt":
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            process.kill()

    timer = threading.Timer(timeout_seconds, kill_process)
    timer.daemon = True
    timer.start()
    return timer


def _close_process(process: subprocess.Popen[bytes]) -> None:
    if process.stdin and not process.stdin.closed:
        process.stdin.close()
    if process.stdout and not process.stdout.closed:
        process.stdout.close()
    if process.stderr and not process.stderr.closed:
        process.stderr.close()
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
