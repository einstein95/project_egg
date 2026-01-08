#!/usr/bin/env python3

import json
import sys
from pathlib import Path

PDS_HEADER = b"pds\n\0"
MAX_FLOPPY_SIZE = 3 * 1024 * 1024  # 3MB
D88_HEADER_SIZE = 0x2B0


class SortedDict(dict):
    """Dictionary that iterates keys in sorted order."""

    def __iter__(self):
        return iter(sorted(super().__iter__()))


def parse_config(data: bytes) -> tuple[str, SortedDict, list[str], list[str]]:
    """Extract title and disk info from config data."""
    title_match = data.find(b"Title\t")
    if title_match == -1:
        title_match = data.find(b"Title\x00")
        while title_match != -1:
            # Ensure it's not Title\x00\x00 and the preceeding byte isn't ASCII
            if (
                title_match + 6 < len(data)
                and data[title_match + 6] != 0
                and (
                    title_match == 0
                    or data[title_match - 1] >= 0x80
                    or data[title_match - 1] < 0x20
                )
            ):
                break
            title_match = data.find(b"Title\x00", title_match + 1)

    if title_match == -1:
        return "Unknown Title", SortedDict(), [], []

    config_section = data[title_match:].split(b"\0\0", 1)[0]
    line_sep = config_section[5]  # \t or \0
    if line_sep == 0x09:  # tab
        config_str = config_section.decode("cp932")
        config_dict = dict(
            line.split("\t", 1) for line in config_str.split("\n") if "\t" in line
        )
    else:  # null
        config_items = [i.decode("cp932") for i in config_section.split(b"\0")]
        try:
            drive1_index = config_items.index("Drive1")
        except ValueError:
            print(config_items)
            exit()
        drive2_index = (
            config_items.index("Drive2")
            if "Drive2" in config_items
            else len(config_items)
        )
        config_dict = dict(
            zip(config_items[:drive1_index:2], config_items[1:drive1_index:2])
        )
        config_dict["Drive1"] = "\t".join(config_items[drive1_index + 1 : drive2_index])
        if drive2_index < len(config_items):
            config_dict["Drive2"] = "\t".join(config_items[drive2_index + 1 :])

    title = config_dict.get("Title", "Unknown Title")
    drive1_info = config_dict.get("Drive1", "").split("\t")
    drive2_info = config_dict.get("Drive2", "").split("\t")

    disk_info = SortedDict(
        info.split(",", 1) for info in drive1_info + drive2_info if "," in info
    )

    return title, disk_info, drive1_info, drive2_info


def build_d88_header(write_protected: bool) -> bytearray:
    """Create the initial D88 disk header."""
    header = bytearray(D88_HEADER_SIZE)
    header[0x1A] = 0x10 if write_protected else 0
    return header


def extract_disk(
    data: bytes, disk_num: int, disk_info: SortedDict, title: str
) -> tuple[str, bytes]:
    """Extract a single disk image from PDS data."""
    write_protected = f"{disk_num}r" in disk_info
    out_data = build_d88_header(write_protected)

    # Limit search to reasonable floppy size
    data = data[:MAX_FLOPPY_SIZE]
    track_num = 0
    last_track = -1

    print(f"\nDisk {disk_num} tracks: ", end="", flush=True)

    pos = 0
    while pos < len(data):
        num_sectors = data[pos]
        if num_sectors == 0:
            break

        pos += 1

        if pos >= len(data):
            break

        track_num = data[pos]  # Track number
        head_num = data[pos + 1]  # Head number
        if track_num < last_track:  # Track numbers should be monotonic
            break

        last_track = track_num
        print(f"{track_num},{head_num}", end=":", flush=True)

        # Write track offset to header
        track_offset_pos = 0x20 + (track_num * 2 + head_num) * 4
        track_offset = len(out_data)
        out_data[track_offset_pos : track_offset_pos + 4] = track_offset.to_bytes(
            4, "little"
        )
        track_num += 1

        # Process all sectors in this track
        for _ in range(num_sectors):
            if pos + 6 > len(data):
                break

            header = data[pos : pos + 6]
            pos += 6

            # Calculate sector size
            sz = 128 << header[3]
            if pos + sz > len(data):
                break

            sector_data = data[pos : pos + sz]
            pos += sz

            # Build sector: header(4) + num_sectors(1) + padding(10) + density(1) + data
            sector = bytearray(header[:4])
            sector.append(num_sectors)
            sector.extend([0] * 10)
            sector.append(header[5] >> 1)
            sector.extend(sector_data)

            out_data.extend(sector)

    # Write total disk size to header
    out_data[0x1C:0x20] = len(out_data).to_bytes(4, "little")

    # Display disk info
    disk_key = f"{disk_num}{'r' if write_protected else ''}"
    disk_label = disk_info.get(disk_key, "No label")

    return f"{title} - {disk_label}", bytes(out_data)


def egg_extract_pds2d88(input_file: str) -> None:
    """
    Extract D88 disk images from PDS format dump file.

    Args:
        input_file: Path to the .DMP file to extract
    """
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        sys.exit(1)

    # Read entire file
    data = input_path.read_bytes()

    # Parse configuration
    title, disk_info, drive1_info, drive2_info = parse_config(data)
    print(f"Title: {title}")
    print(f"Disk info: {disk_info}\n")
    json.dump(
        {
            "title": title,
            "drive1_info": drive1_info,
            "drive2_info": drive2_info,
            "disk_info": disk_info,
        },
        input_path.with_suffix(".json").open("w", encoding="utf-8"),
        ensure_ascii=False,
        indent=2,
    )
    log_file = input_path.with_suffix(".txt")
    log_file.write_text(
        f"Title: {title}\nDrive1: {drive1_info}\nDrive2: {drive2_info}\nDisks: {disk_info}\n"
    )

    # Extract disks
    disk_num = 0
    search_pos = 0

    while search_pos < len(data):
        # Find next PDS header
        header_pos = data.find(PDS_HEADER, search_pos)
        if header_pos == -1:
            break

        # Skip past header
        disk_start = header_pos + len(PDS_HEADER)
        if disk_start >= len(data) or data[disk_start] == 0:
            search_pos = disk_start + 1
            continue

        # Extract disk image
        disk_name, disk_data = extract_disk(
            data[disk_start:], disk_num, disk_info, title
        )

        # Write output file
        output_file = f"{disk_name}.d88"
        Path(output_file).write_bytes(disk_data)
        print(f"  Wrote {output_file} ({len(disk_data)} bytes)\n")

        disk_num += 1
        search_pos = disk_start + 1


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} XXXXXXXX.DMP", file=sys.stderr)
        sys.exit(1)

    egg_extract_pds2d88(sys.argv[1])


if __name__ == "__main__":
    main()
