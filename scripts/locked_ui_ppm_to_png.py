#!/usr/bin/env python3
"""Convert a strictly bounded RGB P6 frame to PNG without third-party deps."""
import argparse
import binascii
import json
import struct
import zlib
from pathlib import Path


def chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def convert(source: Path, destination: Path) -> dict:
    with source.open("rb") as handle:
        if handle.readline() != b"P6\\n":
            raise ValueError("not an RGB P6 fixture")
        dimensions = handle.readline()
        if dimensions != b"1419 611\\n":
            raise ValueError("frame does not match canonical 1419x611 lock")
        if handle.readline() != b"255\\n":
            raise ValueError("unsupported PPM sample depth")
        rgb = handle.read()
    width, height = 1419, 611
    if len(rgb) != width * height * 3:
        raise ValueError("pixel buffer length mismatch")
    lines = b"".join(
        b"\\x00" + rgb[row * width * 3 : (row + 1) * width * 3]
        for row in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    destination.write_bytes(
        b"\\x89PNG\\r\\n\\x1a\\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(lines, level=9))
        + chunk(b"IEND", b"")
    )
    return {
        "evidence_type": "deterministic_native_renderer_empty_state",
        "actual_native_window_capture": False,
        "remote_video_authenticated": False,
        "visual_design_signoff": False,
        "width": width,
        "height": height,
        "pixels": width * height,
        "output": destination.name,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    args = parser.parse_args()
    details = convert(args.input, args.output)
    args.metadata.write_text(json.dumps(details, indent=2) + "\\n", encoding="utf-8")
    print(json.dumps(details))


if __name__ == "__main__":
    main()
