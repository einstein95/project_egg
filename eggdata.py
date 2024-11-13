"""
Usage: eggdata.py <input.exe>

Writes output to a subfolder called `out`. This script extracts embedded
data from a Project EGG executable.
"""

import hashlib
import os
import zlib
from io import BytesIO
from struct import pack, unpack
from sys import argv

import pefile  # type: ignore
from Crypto.Cipher import AES

CHUNK_SIZE = 0x100


def read_dstring(fp, length):
    s = fp.read(length).split(b"\x00")[0]
    return s.decode("latin-1")


def DUMP(EXE_NAME, file, CHUNKS, KEY=b"", METHOD=1):
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
    else:
        decrypted_data = DUMP2(file)

    return decrypted_data


def DUMP2(file):
    # TODO: Make this function work
    tmp = file.tell()
    SIZE = file.seek(0, 2)
    file.seek(tmp)
    if DUMP2_TYPE == 1:
        VAR = unpack("<I", file.read(4))[0]
        VAR ^= 0x18885963
        # XSIZE, TMP = divmod(VAR, 0x4d)
        TMP = VAR % 0x4D
        # XSIZE2 = (VAR * 0x3531dec1) >> 36
        if TMP == 0:
            SIZE -= 4
            open("out/" + name, "wb").write(
                zlib.decompress(file.read(SIZE))
            )  # Should use lzhlib
        else:
            open("out/" + name, "wb").write(file.read(SIZE))
    elif DUMP2_TYPE == 2:
        TMP = unpack("<I", file.read(4))[0]
        if TMP != 0x28 and SIZE >= 0x4000:
            pass
            # filexor "\x33\x53\x93\x63\xA3\xC3\x35\x55\x95\x65\xA5\xC5\x36\x56\x96\x66" OFFSET
            # encryption xmath "(#INPUT# < 4) | (#INPUT# > 4)" 8  # 8bit ROL4 (xmath is 32bit)
        # log NAME OFFSET SIZE


def DUMP_EXTRACT(file):
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
            print(name)
            sign = read_dstring(file, 8)
            if sign == "COMPZIP ":
                # xsize = unpack("<I4x", file.read(8))[0]
                file.seek(8, 1)
                offset = file.tell()
                size -= 0x10
                open("out/" + name, "wb").write(zlib.decompress(file.read(size)))
            else:
                file.seek(-8, 1)
                open("out/" + name, "wb").write(file.read(size))
            file.seek(tmp)


if __name__ == "__main__":
    exe_file = argv[1]
    EXE_NAME = exe_file.encode("utf-8")
    if b".exe" in EXE_NAME.lower():
        EXE_NAME = EXE_NAME[:-4]

    DUMP2_TYPE = 0
    with open(exe_file, "rb") as f:
        d = f.read()
        if b"\x63\x59\x88\x18" in d:
            DUMP2_TYPE = 1
        elif b"\x33\x53\x93\x63\xA3\xC3\x35\x55\x95\x65\xA5\xC5\x36\x56\x96\x66" in d:
            DUMP2_TYPE = 2
        elif b"EGGDATA" not in d:
            print("This version is currently unsupported.")
            exit()

    os.makedirs("out", exist_ok=True)
    pe = pefile.PE(exe_file, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    if not DUMP2_TYPE:
        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:  # type: ignore
            for entry in rsrc.directory.entries:
                if entry.name is not None:
                    if entry.name.__str__().lower() == "config":
                        config_offset = entry.directory.entries[
                            0
                        ].data.struct.OffsetToData
                        config_size = entry.directory.entries[0].data.struct.Size
                    elif entry.name.__str__().lower() == "data":
                        data_offset = entry.directory.entries[
                            0
                        ].data.struct.OffsetToData
                        data_size = entry.directory.entries[0].data.struct.Size

        config = pe.get_memory_mapped_image()[config_offset: config_offset + config_size]  # type: ignore
        data = pe.get_memory_mapped_image()[data_offset: data_offset + data_size]  # type: ignore

        configf = BytesIO(config)
        assert configf.read(8) == b"EGGDATA "
        SIZE = configf.seek(0, 2) - 32
        configf.seek(32)
        CHUNKS = SIZE // CHUNK_SIZE
        decrypted_data = DUMP(EXE_NAME, configf, CHUNKS)
        DUMP_EXTRACT(BytesIO(decrypted_data))

        with open("out/CONFIG", "r", encoding="cp932") as conf_file:
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
        DUMP_EXTRACT(BytesIO(decrypted_data))
    else:
        print("This version is currently unsupported.")
