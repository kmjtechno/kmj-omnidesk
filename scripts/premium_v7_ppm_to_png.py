#!/usr/bin/env python3
"""Strict, dependency-free export of V7's 1672x941 disconnected native RGB frame."""
import argparse
import binascii
import json
import struct
import zlib
from pathlib import Path

WIDTH = 1672
HEIGHT = 941
SOURCE_FRAME = b"1672 941\n"


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def convert(source: Path, destination: Path) -> dict:
    with source.open("rb") as handle:
        if handle.readline() != b"P6\n":
            raise ValueError("not an RGB P6 frame")
        if handle.readline() != SOURCE_FRAME:
            raise ValueError("frame dimensions do not match V7 1672x941 design lock")
        if handle.readline() != b"255\n":
            raise ValueError("unsupported sample depth")
        rgb = handle.read()
    if len(rgb) != WIDTH * HEIGHT * 3:
        raise ValueError("pixel buffer is incomplete or oversized")
    lines = b"".join(
        b"\x00" + rgb[y * WIDTH * 3 : (y + 1) * WIDTH * 3]
        for y in range(HEIGHT)
    )
    ihdr = struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 2, 0, 0, 0)
    destination.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(lines, level=9))
        + png_chunk(b"IEND", b"")
    )
    return {
        "evidence_type": "deterministic_premium_v7_renderer_empty_state",
        "visual_design_signoff": False,
        "actual_native_window_capture": False,
        "remote_video_authenticated": False,
        "width": WIDTH,
        "height": HEIGHT,
        "output": destination.name,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    details = convert(args.input, args.output)
    args.metadata.write_text(json.dumps(details, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(details))


if __name__ == "__main__":
    main()
