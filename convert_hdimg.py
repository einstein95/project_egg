#!/usr/bin/env python3
import argparse
import os
import re
from struct import pack, unpack

parser = argparse.ArgumentParser()
parser.add_argument("diskformat")
parser.add_argument("-d", "--directory", default=".")
args = parser.parse_args()

diskformat = args.diskformat or "img"
workingfolder = args.directory

with open(os.path.join(workingfolder, f"EGGHDIMG-INF"), "rb") as inffile:
    inffile.seek(0x210)
    # Read number of cylinders, heads, sectors per track, sector size
    cyls, heads, sects, ssize = unpack("<IIII", inffile.read(0x10))
    total_sects = cyls * heads * sects
    total_bytes = total_sects * ssize

last_track_num = -1
for filename in os.listdir(workingfolder):
    match = re.search(r"EGGHDIMG(\d+)", filename)
    if match:
        track_num = int(match.group(1))
        if track_num > last_track_num:
            last_track_num = track_num

outputdata = b""
for track_num in range(last_track_num + 1):
    trackfile = f"EGGHDIMG{track_num}"
    if not os.path.exists(os.path.join(workingfolder, trackfile)):
        # print(f"WARNING: EGGHDIMG{track_num} NOT FOUND")
        outputdata += b"\x00" * (sects * ssize)
    else:
        with open(os.path.join(workingfolder, trackfile), "rb") as file:
            outputdata += file.read()

outputdata += b"\x00" * (total_bytes - len(outputdata))
print(
    {
        "cyls": cyls,
        "heads": heads,
        "sects": sects,
        "ssz": ssize,
        "total_sects": total_sects,
        "total_bytes": total_bytes,
        "actual_bytes": len(outputdata),
    }
)

if diskformat == "hdi":
    # 0x00 DWORD Reserved  			Must be set to zero
    # 0x04 DWORD FDDType identifier 		(see below, also called the PDA)
    # 0x08 DWORD HeaderSize 			Size of the entire header in bytes, default for Anex86 "New Disk" is 4096
    # 0x0C DWORD DataSize 			Size of the C/H/S data segment in bytes.  DataSize + HeaderSize = File Size on Disk
    # 0x10 DWORD Bytes per Sector 		Uniform for all sectors
    # 0x14 DWORD Sectors  			Uniform for all tracks
    # 0x18 DWORD Heads 			Uniform for all tracks
    # 0x1C DWORD Cylinders 			Uniform for all tracks
    hdi_header = pack(
        "<4xIIIIIII",
        0,  # FDDType
        0x1000,  # HeaderSize (DOSBox-X doesn't like 32 byte headers)
        len(outputdata),  # DataSize
        ssize,  # Bytes per Sector
        sects,  # Sectors
        heads,  # Heads
        cyls,  # Cylinders
    )
    outputdata = hdi_header + b"\x00" * (0x1000 - len(hdi_header)) + outputdata

with open(os.path.join(workingfolder, f"EGGHDIMG.{diskformat}"), "wb") as outfile:
    outfile.write(outputdata)
