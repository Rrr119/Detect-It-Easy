#!/usr/bin/env python3
"""Create a minimal two-section PE fixture with a high-entropy executable section."""

import random
import struct
from pathlib import Path


OUTPUT = Path(__file__).with_name("generic-packed-pe.exe")
FILE_ALIGNMENT = 0x200
HEADERS_SIZE = 0x200
TEXT_RVA = 0x1000
TEXT_SIZE = 0x6000
DATA_RVA = 0x7000
DATA_SIZE = 0x1000


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def section(name, virtual_size, virtual_address, raw_size, raw_offset, characteristics):
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\x00"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def build():
    text_offset = HEADERS_SIZE
    data_offset = text_offset + align(TEXT_SIZE, FILE_ALIGNMENT)
    image_size = align(DATA_RVA + DATA_SIZE, 0x1000)

    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,
        2,
        0,
        0,
        0,
        0xE0,
        0x0102,
    )

    optional_header = bytearray(0xE0)
    struct.pack_into("<H", optional_header, 0x00, 0x10B)
    struct.pack_into("<I", optional_header, 0x10, TEXT_RVA)
    struct.pack_into("<I", optional_header, 0x1C, 0x00400000)
    struct.pack_into("<I", optional_header, 0x20, 0x1000)
    struct.pack_into("<I", optional_header, 0x24, FILE_ALIGNMENT)
    struct.pack_into("<I", optional_header, 0x38, image_size)
    struct.pack_into("<I", optional_header, 0x3C, HEADERS_SIZE)
    struct.pack_into("<H", optional_header, 0x44, 3)
    struct.pack_into("<I", optional_header, 0x5C, 16)

    sections = (
        section(b".text", TEXT_SIZE, TEXT_RVA, TEXT_SIZE, text_offset, 0xE0000020)
        + section(b".data", DATA_SIZE, DATA_RVA, DATA_SIZE, data_offset, 0xC0000040)
    )

    headers = dos_header + b"PE\x00\x00" + file_header + optional_header + sections
    assert len(headers) <= HEADERS_SIZE
    headers = headers.ljust(HEADERS_SIZE, b"\x00")

    random.seed(0x50455A4F)
    text_data = bytes(random.getrandbits(8) for _ in range(TEXT_SIZE))
    data_data = b"\x00" * DATA_SIZE

    OUTPUT.write_bytes(headers + text_data + data_data)


if __name__ == "__main__":
    build()
    print(OUTPUT)
