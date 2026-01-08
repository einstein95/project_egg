#!/usr/bin/env python3
"""
CNPFVR Archive Extractor
Extracts files from CNPFVR format archives (versions 02, 06, 07, B5)
All strings are encoded in CP932 (Shift-JIS)
"""

import os
import struct
import sys
from pathlib import Path, PureWindowsPath


def read_header(f):
    """Read the archive header"""
    idstring = f.read(8).decode()
    filesize = struct.unpack("<I", f.read(4))[0]
    dataoff = struct.unpack("<I", f.read(4))[0]
    files = struct.unpack("<I", f.read(4))[0]

    return {
        "idstring": idstring,
        "filesize": filesize,
        "dataoff": dataoff,
        "files": files,
    }


def parse_filename_csv(csv_data):
    """Parse the CSV filename list (single line, comma-separated)"""
    csv_str = csv_data.decode("cp932", errors="ignore").strip("\x00")

    # Split by comma and pair them up (filename, type, filename, type, ...)
    parts = [p.strip() for p in csv_str.split(",") if p.strip()]

    files_info = []
    for i in range(0, len(parts), 2):
        if i + 1 < len(parts):
            files_info.append({"filename": parts[i], "type": parts[i + 1]})
        elif i < len(parts):
            # Odd number of parts, last one has no type
            files_info.append({"filename": parts[i], "type": "unknown"})

    return files_info


def lzss_decompress(compressed_data, decompressed_size):
    """
    LZSS decompression algorithm
    Standard LZSS with 4096-byte sliding window
    """
    output = bytearray()
    ring_buffer = bytearray(4096)
    ring_pos = 0xFEE  # Standard LZSS initial position

    i = 0
    while i < len(compressed_data) and len(output) < decompressed_size:
        flags = compressed_data[i]
        i += 1

        for bit in range(8):
            if len(output) >= decompressed_size:
                break

            if i >= len(compressed_data):
                break

            if flags & (1 << bit):
                # Literal byte
                byte = compressed_data[i]
                i += 1
                output.append(byte)
                ring_buffer[ring_pos] = byte
                ring_pos = (ring_pos + 1) % 4096
            else:
                # Length-distance pair
                if i + 1 >= len(compressed_data):
                    break

                byte1 = compressed_data[i]
                byte2 = compressed_data[i + 1]
                i += 2

                offset = byte1 | ((byte2 & 0xF0) << 4)
                length = (byte2 & 0x0F) + 3

                for _ in range(length):
                    if len(output) >= decompressed_size:
                        break
                    byte = ring_buffer[offset]
                    output.append(byte)
                    ring_buffer[ring_pos] = byte
                    ring_pos = (ring_pos + 1) % 4096
                    offset = (offset + 1) % 4096

    return bytes(output[:decompressed_size])


def extract_file(f, filename):
    """Extract a single file from the archive"""
    comp = struct.unpack("B", f.read(1))[0]
    file_type = struct.unpack("B", f.read(1))[0]
    size = struct.unpack("<I", f.read(4))[0]

    if comp == 1:
        # Compressed file (LZSS)
        decsize = struct.unpack("<I", f.read(4))[0]
        compressed_data = f.read(size - 4)

        try:
            # LZSS decompression
            data = lzss_decompress(compressed_data, decsize)
            print(
                f"  Extracted (LZSS): {filename} ({len(compressed_data)} -> {len(data)} bytes)"
            )
        except Exception as e:
            # If decompression fails, save the raw compressed data
            data = compressed_data
            print(f"  Warning: Could not decompress {filename}: {e}")
    else:
        # Uncompressed file
        data = f.read(size)
        print(f"  Extracted: {filename} ({size} bytes)")

    if file_type == 11:
        # Game file
        if b"Dr0Wy3K" in data:
            # Find signature and patch
            sig_index = data.find(b"Dr0Wy3K")
            if sig_index != -1 and sig_index + 8 < len(data):
                patched_data = bytearray(data)
                patched_data[sig_index + 7 : sig_index + 7 + 0x40] = (
                    b"\x01\x01\x01" + b"\x20" * 60 + b"\x00"
                )
                data = bytes(patched_data)
                print(f"    Patched protection in {filename}")
        if b"CBy3fc3" in data:
            print(
                f"    Note: Protection found in {filename}, manual patching may be required."
            )
    # Write the extracted file
    output_path = filename
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "wb") as out:
        out.write(data)

    return len(data)


def extract_archive(archive_path):
    """Extract all files from a CNPFVR archive"""
    archive_path = Path(archive_path)

    with open(archive_path, "rb") as f:
        # Read header
        header = read_header(f)
        print(f"Archive: {archive_path.name}")
        print(f"ID String: {header['idstring']}")
        print(f"File Size: {header['filesize']} bytes")
        print(f"Data Offset: {header['dataoff']} (0x{header['dataoff']:X})")
        print(f"File Count: {header['files']}")
        print()

        # Read filename CSV
        csv_size = header["dataoff"] - 0x14  # 0x14 = header size (20 bytes)
        csv_data = f.read(csv_size)
        files_info = parse_filename_csv(csv_data)

        # Ensure we're at the correct position
        f.seek(header["dataoff"])

        # Extract each file
        print(f"Extracting {header['files']} files")
        print("-" * 60)

        for i in range(header["files"]):
            if i < len(files_info):
                filename = Path(PureWindowsPath(files_info[i]["filename"]))
            else:
                # Fallback filename if CSV parsing failed
                filename = f"file_{i:04d}.bin"

            extract_file(f, filename)

        print("-" * 60)
        print(f"Extraction complete!")


def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_cnpfvr.py <archive_file> [output_directory]")
        print("\nExtracts files from CNPFVR format archives")
        sys.exit(1)

    archive_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(archive_file):
        print(f"Error: File '{archive_file}' not found")
        sys.exit(1)

    try:
        extract_archive(archive_file)
    except Exception as e:
        print(f"Error during extraction: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
