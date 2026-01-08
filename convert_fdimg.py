#!/usr/bin/env python3
import argparse
import os
import re
from struct import pack, unpack

# FDC status codes if they ever need implementing
# 10h  the data has DDAM
# 20h  ?
# 30h  warning 'try to access over final track'
# 40h  Fault signal from FDD,Recalibrate error
# 50h  time out error
# 60h  FDD not ready
# 70h  detected write protected
# 80h  ?
# 90h  ?
# A0h  ID CRC error
# B0h  Data CRC error
# C0h  cannot find specified sector in the track
# D0h  cannot find specified cylinder
# E0h  cannot find Address Mark
# F0h  cannot find DAM or DDAM when reading datas.

parser = argparse.ArgumentParser()
parser.add_argument("diskformat")
parser.add_argument("-d", "--directory", default=".")
args = parser.parse_args()

diskformat = args.diskformat
workingfolder = args.directory
disks = []
debug = False

if debug:
    print(f"[DEBUG] Disk format: {diskformat}")
    print(f"[DEBUG] Working folder: {workingfolder}")

for filename in os.listdir(workingfolder):
    match = re.search(r"EGGFDIMG(\d+)-INF", filename)
    if match:
        disks.append(match.group(1))
        if debug:
            print(f"[DEBUG] Found disk: {match.group(1)}")

if debug:
    print(f"[DEBUG] Total disks found: {len(disks)}")

for disk in disks:
    if debug:
        print(f"\n[DEBUG] Processing disk: {disk}")
    tracksizes = []
    outputdata = b""
    with open(os.path.join(workingfolder, f"EGGFDIMG{disk}-INF"), "rb") as inffile:
        inffile.seek(0x200)
        sha1hash = inffile.read(0x10)
        _, readonly, numtracks = unpack("<III", inffile.read(12))
        if debug:
            print(
                f"[DEBUG] SHA1: {sha1hash.hex()}, readonly: {readonly}, numtracks: {numtracks}"
            )

    disktype = 0x20 if numtracks > 84 else 0
    if debug:
        print(f"[DEBUG] Disk type: {disktype}")

    for tracknum in range(numtracks):
        if not os.path.exists(
            os.path.join(workingfolder, f"EGGFDIMG{disk}-{tracknum}")
        ):
            if debug:
                print(f"[DEBUG] Track {tracknum} not found, skipping")
            if diskformat == "d88":
                tracksizes.append(0)
            continue

        filename = f"EGGFDIMG{disk}-{tracknum}"
        with open(os.path.join(workingfolder, filename), "rb") as file:
            if debug:
                print(f"[DEBUG] Reading {filename}")
            numsectors = unpack("<I", file.read(4))[0]
            if debug:
                print(f"[DEBUG] Number of sectors: {numsectors}")
            sectoroffs = unpack(f"<{numsectors}I", file.read(numsectors * 4))
            tracksize = 0
            for i, sectoroff in enumerate(sectoroffs):
                file.seek(sectoroff)
                c, h, s, l, density, ddam, unk, datasize = unpack(
                    "<BBBBBBHI", file.read(12)
                )
                if debug:
                    print(
                        f"[DEBUG] S{i:02X}: C={c:02X}, H={h}, S={s:02X}, L={l}, Density={density}, DDAM={ddam}, datasize={datasize}"
                    )
                if datasize > 0xFFFF:
                    raise ValueError("Invalid sector length found")

                if 128 << l != datasize:
                    print(
                        f"[WARNING] Sector size mismatch (expected {128 << l}, got {datasize})"
                    )

                if density not in [0, 1]:
                    print(f"[WARNING] Warning: Unknown density (got {density})")

                if unk != 0:
                    print(f"[WARNING] Unknown value={unk}")

                if diskformat == "d88":
                    outputdata += pack(
                        "<"
                        "B"  # 00h C
                        "B"  # 01h H
                        "B"  # 02h S
                        "B"  # 03h L
                        "H"  # 04h-05h number of sectors
                        "B"  # 06h Density (00h=double; 40h=single)
                        "B"  # 07h DDAM
                        "6x"
                        "H",  # 0Eh Data size
                        c,
                        h,
                        s,
                        l,
                        numsectors,
                        0x40 if not density else 0,
                        0x10 if ddam else 0,
                        datasize,
                    )

                outputdata += file.read(datasize)
                tracksize += datasize + 0x10
            tracksizes.append(tracksize)
            if debug:
                print(f"[DEBUG] Track {tracknum} size: {tracksize}")

    if debug:
        print(f"[DEBUG] Total tracks processed: {len(tracksizes)}")
        print(f"[DEBUG] Output data size: {len(outputdata)}")

    if diskformat == "d88":
        numtracks = max(numtracks, 164)
        track_table_size = numtracks * 4
        alignment_padding = track_table_size % 16
        startoff = 0x20 + track_table_size + alignment_padding
        if debug:
            print(f"[DEBUG] D88 header - numtracks: {numtracks}, startoff: {startoff}")

        track_offsets = []
        current_offset = startoff

        for tracksize in tracksizes:
            track_offsets.append(pack("<I", current_offset if tracksize > 0 else 0))
            if tracksize > 0:
                current_offset += tracksize

        d88_header = pack("26xBB", 0x10 if readonly else 0, disktype)
        d88_header += pack("<I", len(outputdata) + startoff)
        d88_header += b"".join(track_offsets)
        d88_header += b"\x00" * (startoff - len(d88_header))
        if debug:
            print(f"[DEBUG] D88 header size: {len(d88_header)}")

        # Write complete disk image
        output_path = os.path.join(workingfolder, f"disk_{disk}.d88")
        with open(output_path, "wb") as disk:
            disk.write(d88_header + outputdata)
        if debug:
            print(f"[DEBUG] Written D88 file: {output_path}")

    elif diskformat == "dsk":
        output_path = os.path.join(workingfolder, f"disk_{disk}.dsk")
        with open(output_path, "wb") as disk:
            disk.write(outputdata)
        if debug:
            print(f"[DEBUG] Written DSK file: {output_path}")

if debug:
    print("\n[DEBUG] Conversion complete")
