#!/usr/bin/env python3
"""Regenerate assets/winfw-mcp.ico.

The icon is generated rather than authored: the tool needs a logo that reads as a firewall at
16 pixels, and a few lines of arithmetic are easier to review and to redo than a binary blob
committed without a history. Sizes: 16, 32 and 48 pixels, 32 bits per pixel.

Run from anywhere: `python assets/make_icon.py`.
"""

import struct
from pathlib import Path

SIZES = (16, 32, 48)

# A blue disc with a light brick pattern on top.
BLUE = (0x1F, 0x4E, 0x79)
BRICK = (0x7F, 0xB5, 0xD6)
MORTAR = (0xED, 0xF2, 0xF7)


def pixel(x: int, y: int, size: int):
    """Colour of one pixel from the top left, or None when it is transparent."""
    centre = (size - 1) / 2
    radius = size / 2 - 0.5

    dx, dy = x - centre, y - centre
    if dx * dx + dy * dy > radius * radius:
        return None

    # Courses of four pixels, offset every other row, so it reads as a wall at any size.
    row, col = y // 4, x % 8
    if (y % 4) == 0:
        return MORTAR
    if (row % 2 == 0 and col in (0, 1)) or (row % 2 == 1 and (col + 4) % 8 in (0, 1)):
        return MORTAR

    return BRICK if (x + y) % 2 == 0 else BLUE


def image(size: int) -> bytes:
    """One directory entry's data: BITMAPINFOHEADER, colour rows, AND mask."""
    header = struct.pack(
        "<IiiHHIIiiII",
        40,           # bmiSize
        size,         # width
        size * 2,     # height: colour plus mask
        1,            # planes
        32,           # bit count
        0,            # compression
        0,            # size of raw data, ignored for a resource icon
        0,            # x pixels per metre
        0,            # y pixels per metre
        0,            # colours used
        0,            # important colours
    )

    colour = bytearray()
    for y in range(size - 1, -1, -1):  # device bitmaps are bottom-up
        for x in range(size):
            rgb = pixel(x, y, size)
            # Stored as BGRA, and a fully transparent pixel must zero all four bytes.
            colour += bytes((rgb[2], rgb[1], rgb[0], 255)) if rgb else b"\x00\x00\x00\x00"

    # The AND mask is one bit per pixel, each row padded to a multiple of 32 bits.
    mask_row = ((size + 31) // 32) * 4
    mask = bytearray(mask_row * size)

    return header + bytes(colour) + bytes(mask)


def main() -> None:
    out = Path(__file__).with_name("winfw-mcp.ico")
    data = {size: image(size) for size in SIZES}

    entry_size = 16
    offset = 6 + entry_size * len(SIZES)

    out_bytes = bytearray(struct.pack("<HHH", 0, 1, len(SIZES)))
    for size in SIZES:
        out_bytes += struct.pack(
            "<BBBBHHII",
            size if size < 256 else 0,
            size if size < 256 else 0,
            0,      # palette entries
            0,      # reserved
            1,      # planes
            32,     # bit count
            len(data[size]),
            offset,
        )
        offset += len(data[size])

    for size in SIZES:
        out_bytes += data[size]

    out.write_bytes(bytes(out_bytes))
    print(f"{out} written: {len(out_bytes)} bytes")


if __name__ == "__main__":
    main()
