#!/usr/bin/env python3
"""Reject AARs missing the expected Rust libraries or ELF architecture."""

import argparse
import struct
import zipfile

ARCHITECTURES = {
    "arm64-v8a": (2, 183), "armeabi-v7a": (1, 40),
    "x86": (1, 3), "x86_64": (2, 62),
}


def check_aar(path):
    with zipfile.ZipFile(path) as archive:
        for abi, (elf_class, machine) in ARCHITECTURES.items():
            for library in ("libtcx.so", "libconnector.so"):
                name = f"jni/{abi}/{library}"
                if archive.namelist().count(name) != 1:
                    raise ValueError(f"Missing or duplicate native library: {name}")
                with archive.open(name) as entry:
                    header = entry.read(20)
                if (len(header) < 20 or header[:4] != b"\x7fELF"
                        or header[4] != elf_class or header[5] != 1
                        or struct.unpack_from("<H", header, 16)[0] != 3
                        or struct.unpack_from("<H", header, 18)[0] != machine):
                    raise ValueError(f"Invalid ELF shared library for {abi}: {name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aar")
    args = parser.parse_args()
    try:
        check_aar(args.aar)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"AAR validation failed: {error}\n")
    print("AAR contains both Rust shared libraries for all four Android ABIs.")
