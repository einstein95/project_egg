#!/usr/bin/env python3
import os
import re
from struct import pack, unpack
from sys import argv, exit

diskformat = argv[1]
disks = []

tracksizes = []

for filename in os.listdir("."):
    match = re.search(r"EGGFDIMG(\d+)-INF", filename)
    if match:
        disks.append(match.group(1))

for disk in disks:
    outputdata = b""
    with open(f"EGGFDIMG{disk}-INF", "rb") as inffile:
        inffile.seek(0x200)
        sha1hash = inffile.read(0x10)
        _, readonly, numtracks = unpack("<III", inffile.read(12))
        print(sha1hash.hex(), readonly, numtracks)

    if readonly == 1:
        readonly = 0x10

    if numtracks > 84:
        disktype = 0x20
    else:
        disktype = 0

    for tracknum in range(numtracks):
        if not os.path.exists(f"EGGFDIMG{disk}-{tracknum}"):
            print(f"WARNING: EGGFDIMG{disk}-{tracknum} NOT FOUND")
            if diskformat == "d88":
                tracksizes.append(0)
            continue

        filename = f"EGGFDIMG{disk}-{tracknum}"
        with open(filename, "rb") as file:
            # print(filename)
            numsectors = unpack("<I", file.read(4))[0]
            sectoroffs = []
            for _ in range(numsectors):
                sectoroff = unpack("<I", file.read(4))[0]
                sectoroffs.append(sectoroff)

            if diskformat == "d88":
                tracksize = 0
                for sectoroff in sectoroffs:
                    file.seek(sectoroff)
                    head = file.read(12)
                    # a, b, c = unpack('<III', head)
                    # print(f'{a:08x}\t{b:08x}\t{c:08x}')
                    sectorsize = unpack("<I", head[-4:])[0]
                    if sectorsize >= 0xFFFF:
                        exit("Invalid sector length found")
                    else:
                        outputdata += head[:4]
                        outputdata += pack("<B9xH", numsectors, sectorsize)
                        outputdata += file.read(sectorsize)
                    tracksize += sectorsize + 0x10
                tracksizes.append(tracksize)
            elif diskformat in ["dsk", "fdi"]:
                for sectoroff in sectoroffs:
                    file.seek(sectoroff)
                    head = file.read(12)
                    sectorsize = unpack("<I", head[-4:])[0]
                    outputdata += file.read(sectorsize)

    if diskformat == "d88":
        output_header = pack("26xBB", readonly, disktype)
        if len(tracksizes) > 164:
            startoff = 0x20 + len(tracksizes) * 4 + ((len(tracksizes) * 4) % 16)
        else:
            startoff = 0x2B0  # 0x20 + 164 * 4 + ((164 * 4) % 16)
        offset = startoff
        output_header += pack("<I", len(outputdata) + offset)
        for tracksize in tracksizes:
            if tracksize > 0:
                # print(offset, tracksize)
                output_header += pack("<I", offset)
                offset += tracksize
            else:
                output_header += pack("<I", 0)

        output_header += b"\x00" * abs(startoff - len(output_header))

        with open(f"disk_{disk}.d88", "wb") as disk:
            disk.write(output_header + outputdata)

    elif diskformat == "dsk":
        with open(f"disk_{disk}.dsk", "wb") as disk:
            disk.write(outputdata)

    elif diskformat == "fdi":
        output_header = pack(
            "<IIIIIIII4064x", 0, 0x90, 0x1000, 0x134000, 0x400, 8, 2, 77
        )
        with open(f"disk_{disk}.fdi", "wb") as disk:
            disk.write(output_header + outputdata)
