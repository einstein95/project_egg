"""
Usage: eggdata.py <input.exe>

Writes output to a subfolder called `out`. This script extracts embedded
data from a Project EGG executable.
"""

import hashlib
import os
import re
import subprocess
import zlib
from io import BytesIO
from pathlib import Path
from struct import pack, unpack
from sys import argv, stderr

import pefile  # type: ignore
from Crypto.Cipher import AES

CHUNK_SIZE = 0x100


def read_dstring(fp, length):
    s = fp.read(length).split(b"\x00")[0]
    return s.decode("latin-1")


def DUMP(EXE_NAME, file, CHUNKS, KEY=b"", METHOD=1) -> bytes:
    if METHOD == 1:
        if not KEY:
            m = hashlib.md5(EXE_NAME)
            KEY = bytearray([i ^ 0xFF for i in m.digest()])
        else:
            KEY = bytearray(KEY)

        KEY_INC = unpack("<I", KEY[0:4])[0]
        decrypted_data = b""
        for i in range(CHUNKS):
            KEY[0:4] = pack("<I", KEY_INC ^ i)
            cipher = AES.new(bytes(KEY), AES.MODE_ECB)
            d = file.read(CHUNK_SIZE)
            decrypted_data += cipher.decrypt(d)

        return decrypted_data
    else:
        DUMP2(file)
        return b""


def DUMP2(file: BytesIO, dump_folder: str = "out") -> None:
    tmp = file.tell()
    SIZE = file.seek(0, 2)
    file.seek(tmp)
    if DUMP2_TYPE == 1:
        VAR = unpack("<I", file.read(4))[0]
        VAR ^= 0x18885963
        # XSIZE, TMP = divmod(VAR, 0x4d)
        TMP = VAR % 0x4D
        name = f"dump_{VAR:08x}.bin"
        # XSIZE2 = (VAR * 0x3531dec1) >> 36
        if TMP == 0:
            SIZE -= 4
            open(f"{dump_folder}/{name}", "wb").write(
                zlib.decompress(file.read(SIZE))
            )  # Should use lzhlib
        else:
            open(f"{dump_folder}/{name}", "wb").write(file.read(SIZE))
    elif DUMP2_TYPE == 2:
        TMP = unpack("<I", file.read(4))[0]
        if TMP != 0x28 and SIZE >= 0x4000:
            # XOR key pattern
            xor_key = (
                b"\x33\x53\x93\x63\xa3\xc3\x35\x55\x95\x65\xa5\xc5\x36\x56\x96\x66"
            )

            # Read the data starting from current offset
            OFFSET = file.tell()
            data = bytearray(file.read())

            # Apply XOR with repeating key
            for i in range(len(data)):
                data[i] ^= xor_key[(OFFSET + i) % len(xor_key)]

            # Apply ROL4 (rotate left by 4 bits) on each byte
            for i in range(len(data)):
                byte = data[i]
                data[i] = ((byte << 4) | (byte >> 4)) & 0xFF

            # Reset file position and write decrypted data back
            file.seek(OFFSET)
            file.write(bytes(data))
            file.seek(OFFSET)
        # log NAME OFFSET SIZE


def DUMP_EXTRACT(file: BytesIO, dump_folder: str = "out") -> None:
    while True:
        type = read_dstring(file, 4)
        if type == "END":
            break
        elif type == "NEXT":
            offset = unpack("<I", file.read(4))[0]
            offset *= CHUNK_SIZE
            file.seek(offset)
        else:
            offset, size = unpack("<II", file.read(8))
            name = read_dstring(file, 20)
            offset *= CHUNK_SIZE
            # name += ".bin"
            tmp = file.tell()
            file.seek(offset)
            # print(name)
            sign = read_dstring(file, 8)
            if sign == "COMPZIP ":
                # xsize = unpack("<I4x", file.read(8))[0]
                file.seek(8, 1)
                offset = file.tell()
                size -= 0x10
                open(f"{dump_folder}/{name}", "wb").write(
                    zlib.decompress(file.read(size))
                )
            else:
                file.seek(-8, 1)
                open(f"{dump_folder}/{name}", "wb").write(file.read(size))
            file.seek(tmp)


if __name__ == "__main__":
    for exe_file in argv[1:]:
        EXE_STEM = Path(exe_file).stem
        EXE_NAME = EXE_STEM.encode("utf-8")
        dump_folder = f"{EXE_STEM}_out"

        DUMP2_TYPE = 0
        with open(exe_file, "rb") as f:
            d = f.read()
            if b"\x63\x59\x88\x18" in d:
                DUMP2_TYPE = 1
            elif (
                b"\x33\x53\x93\x63\xa3\xc3\x35\x55\x95\x65\xa5\xc5\x36\x56\x96\x66" in d
            ):
                DUMP2_TYPE = 2

        if not DUMP2_TYPE and not b"EGGDATA" in d:
            print(
                "This version is currently unsupported (unknown encryption).",
                file=stderr,
            )
            continue

        os.makedirs(dump_folder, exist_ok=True)
        pe = pefile.PE(exe_file, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:  # type: ignore
            for entry in rsrc.directory.entries:
                if entry.name is not None:
                    rsrc_name = entry.name.string.decode().lower()
                    if rsrc_name == "conf":
                        print(
                            "This version is currently unsupported (unknown encryption).",
                            file=stderr,
                        )
                        exit(1)
                    if rsrc_name == "config":
                        config_offset = entry.directory.entries[
                            0
                        ].data.struct.OffsetToData
                        config_size = entry.directory.entries[0].data.struct.Size
                    elif rsrc_name == "data":
                        data_offset = entry.directory.entries[
                            0
                        ].data.struct.OffsetToData
                        data_size = entry.directory.entries[0].data.struct.Size
                    else:
                        print("Unknown resource:", rsrc_name)

        config = pe.get_memory_mapped_image()[config_offset : config_offset + config_size]  # type: ignore
        data = pe.get_memory_mapped_image()[data_offset : data_offset + data_size]  # type: ignore

        configf = BytesIO(config)
        assert configf.read(8) == b"EGGDATA "
        SIZE = configf.seek(0, 2) - 32
        configf.seek(32)
        CHUNKS = SIZE // CHUNK_SIZE
        decrypted_data = DUMP(EXE_NAME, configf, CHUNKS)
        DUMP_EXTRACT(BytesIO(decrypted_data), dump_folder=dump_folder)

        with open(f"{dump_folder}/CONFIG", "r", encoding="cp932") as conf_file:
            configl = conf_file.read().splitlines()
            config = dict(i.split("=") for i in configl)
            print(config)

        dataf = BytesIO(data)
        assert dataf.read(8) == b"EGGDATA "
        SIZE = dataf.seek(0, 2) - 32
        dataf.seek(32)
        CHUNKS = SIZE // CHUNK_SIZE
        decrypted_data = DUMP(
            EXE_NAME, dataf, CHUNKS, KEY=bytes.fromhex(config["YekTpyrc"])
        )
        num_disks = int(config.get("FDImages", "0"))
        DUMP_EXTRACT(BytesIO(decrypted_data), dump_folder=dump_folder)
        subprocess.run(
            [
                "python3",
                Path(__file__).parent / "convert_fdimg.py",
                "-d",
                dump_folder,
                "d88",
            ]
        )
        disk_names = {}
        for n in range(2):
            for k in config.keys():
                if re.search(f"FD{n}Assign\\d+Index", k):
                    disk_names[int(config[k])] = config.get(
                        k.replace("Index", "Title"), f"Disk {int(config[k])}"
                    )
        for n in range(num_disks):
            disk_name = f'{EXE_STEM} - {config["EGGTitle"]} - {disk_names[n]}.d88'
            print(disk_name, file=stderr)
            subprocess.run(
                [
                    "mv",
                    f"{dump_folder}/disk_{n}.d88",
                    disk_name,
                ]
            )
        # if config.get("PC98_BootHD", "0") == "1" or config.get("HDImageID", False):
        if Path(f"{dump_folder}/EGGHDIMG-INF").exists():
            subprocess.run(
                [
                    "python3",
                    Path(__file__).parent / "convert_hdimg.py",
                    "-d",
                    dump_folder,
                    "hdi",
                ]
            )
            hdd_name = f'{config["EGGTitle"]}.hdi'
            print(hdd_name, file=stderr)
            subprocess.run(
                [
                    "mv",
                    f"{dump_folder}/EGGHDIMG.hdi",
                    hdd_name,
                ]
            )
