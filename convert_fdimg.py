#!/usr/bin/env python3
import argparse
import os
import re
from struct import pack, unpack

parser = argparse.ArgumentParser()
parser.add_argument("diskformat")
parser.add_argument("-d", "--directory", default=".")
args = parser.parse_args()

diskformat = args.diskformat
workingfolder = args.directory
disks = []

for filename in os.listdir(workingfolder):
    match = re.search(r"EGGFDIMG(\d+)-INF", filename)
    if match:
        disks.append(match.group(1))

for disk in disks:
    tracksizes = []
    outputdata = b""
    with open(os.path.join(workingfolder, f"EGGFDIMG{disk}-INF"), "rb") as inffile:
        inffile.seek(0x200)
        sha1hash = inffile.read(0x10)
        _, readonly, numtracks = unpack("<III", inffile.read(12))
        print(sha1hash.hex(), readonly, numtracks)

    if readonly == 1:
        readonly = 0x10

    disktype = 0x20 if numtracks > 84 else 0

    for tracknum in range(numtracks):
        if not os.path.exists(
            os.path.join(workingfolder, f"EGGFDIMG{disk}-{tracknum}")
        ):
            # print(f"WARNING: EGGFDIMG{disk}-{tracknum} NOT FOUND")
            if diskformat == "d88":
                tracksizes.append(0)

            continue

        filename = f"EGGFDIMG{disk}-{tracknum}"
        with open(os.path.join(workingfolder, filename), "rb") as file:
            print(filename)
            numsectors = unpack("<I", file.read(4))[0]
            sectoroffs = unpack(f"<{numsectors}I", file.read(numsectors * 4))
            tracksize = 0
            for sectoroff in sectoroffs:
                file.seek(sectoroff)
                c, h, s, l, _, datasize = unpack("<BBBBII", file.read(12))
                if datasize > 0xFFFF:
                    raise ValueError("Invalid sector length found")

                if diskformat == "d88":
                    outputdata += pack("<BBBBH8xH", c, h, s, l, numsectors, datasize)

                outputdata += file.read(datasize)
                tracksize += datasize + 0x10
            tracksizes.append(tracksize)

    if diskformat == "d88":
        numtracks = max(numtracks, 164)
        track_table_size = numtracks * 4
        alignment_padding = track_table_size % 16
        startoff = 0x20 + track_table_size + alignment_padding

        track_offsets = []
        current_offset = startoff

        for tracksize in tracksizes:
            track_offsets.append(pack("<I", current_offset if tracksize > 0 else 0))
            if tracksize > 0:
                current_offset += tracksize

        d88_header = pack("26xBB", readonly, disktype)
        d88_header += pack("<I", len(outputdata) + startoff)
        d88_header += b"".join(track_offsets)
        d88_header += b"\x00" * (startoff - len(d88_header))

        # Write complete disk image
        output_path = os.path.join(workingfolder, f"disk_{disk}.d88")
        with open(output_path, "wb") as disk:
            disk.write(d88_header + outputdata)

    elif diskformat == "dsk":
        with open(os.path.join(workingfolder, f"disk_{disk}.dsk"), "wb") as disk:
            disk.write(outputdata)
