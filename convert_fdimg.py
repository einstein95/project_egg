#!/usr/bin/env python3
import os
import re
from struct import pack, unpack
from sys import argv, exit

diskformat = argv[1]
try:
    workingfolder = argv[2]
except IndexError:
    workingfolder = "."
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

    if numtracks > 84:
        disktype = 0x20
    else:
        disktype = 0

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
            sectoroffs: list[int] = []
            # for _ in range(numsectors):
            #   sectoroffs.append(unpack("<I", file.read(4))[0])
            sectoroffs += unpack(f"<{numsectors}I", file.read(numsectors * 4))

            tracksize = 0
            for sectoroff in sectoroffs:
                file.seek(sectoroff)
                c, h, s, l, _, datasize = unpack("<BBBBII", file.read(12))
                if datasize >= 0xFFFF:
                    exit("Invalid sector length found")
                else:
                    if diskformat == "d88":
                        outputdata += pack(
                            "<BBBBH8xH", c, h, s, l, numsectors, datasize
                        )
                    outputdata += file.read(datasize)
                tracksize += datasize + 0x10
            tracksizes.append(tracksize)

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

        with open(os.path.join(workingfolder, f"disk_{disk}.d88"), "wb") as disk:
            disk.write(output_header + outputdata)

    elif diskformat == "dsk":
        with open(os.path.join(workingfolder, f"disk_{disk}.dsk"), "wb") as disk:
            disk.write(outputdata)

    elif diskformat == "fdi":
        # 0x90 = 1.2M
        # 0x30 = 1.44M
        # 0x10 = 640K/720K
        fdd_type = 0x90
        header_size = 32
        data_size = len(outputdata)
        bps = 0x400
        output_header = pack(
            f"<4xIIIIIII{header_size - 32}x",
            fdd_type,
            header_size,
            data_size,
            bps,
            s,
            h + 1,
            c + 1,
        )
        with open(os.path.join(workingfolder, f"disk_{disk}.fdi"), "wb") as disk:
            disk.write(output_header + outputdata)
