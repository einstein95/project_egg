from operator import xor
from sys import argv

files = argv[1:]
operations = {
    # ?: (b"\x33\x53\x93\x63\xa3\xc3\x35\x55\x95\x65\xa5\xc5\x36\x56\x96\x66", ?),
    0x80: (b"\x4b\x1d\x4b\xdb\x4b\xfa\x8b\xdb\x1b\xfb\xcb\x4b\x0b\xcb\xea\xdd", 4),
    0x81: (b"\xa5\x8e\xa5\xed\xa5\x7d\xc5\xed\x8d\xfd\xe5\xa5\x85\xe5\x75\xee", 3),
    # 0x82: (b"????????????????", 2),
    # 0x83: (b"????????????????", 1),
    # 0x84: (b"????????????????", 4),
    0x85: (b"\xa5\x7d\xc5\xed\x8d\xfd\xe5\xa5\x85\xe5\x75\xee\xa5\x8e\xa5\xed", 3),
    0x86: (b"\xd2\xbe\xe2\xf6\xc6\xfe\xf2\xd2\xc2\xf2\xba\x77\xd2\x47\xd2\xf6", 2),
    0x87: (b"\x69\x5f\x71\x7b\x63\x7f\x79\x69\x61\x79\x5d\xbb\x69\xa3\x69\x7b", 1),
    # 0x88: (b"????????????????", 4),
    # 0x89: (b"????????????????", 3),
    # 0x8A: (b"????????????????", 2),
    # 0x8B: (b"????????????????", 1),
    # 0x8C: (b"????????????????", 4),
    0x8D: (b"\x85\xe5\x75\xee\xa5\x8e\xa5\xed\xa5\x7d\xc5\xed\x8d\xfd\xe5\xa5", 3),
    # 0x8E: (b"????????????????", 2),
    # 0x8F: (b"????????????????", 1),
}


def xor_bytes(data: bytearray, key: bytes) -> bytearray:
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return data


def rotate_op(data: bytearray, shift: int) -> bytearray:
    # Rotate right by shift bits
    for i in range(len(data)):
        data[i] = ((data[i] >> shift) | (data[i] << (8 - shift))) & 0xFF
    return data


for fn in files:
    with open(fn, "rb") as f:
        operation = f.read(1)[0]
        data = bytearray(f.read())

    if operation == 0 and not data or len(data) == 1:
        print(f"File {fn} is empty, skipping.")
        continue

    print(data[:16].hex())
    if operation in operations and len(data) % 16 != 0:
        print(f"[WARNING] File {fn} size not divisable by 16")
        xor_key, shift = operations[operation]
    elif not operation in operations or len(data) % 16 != 0:
        print(
            f"Unknown operation {operation} in file {fn}, using default deobfuscation"
        )
        data = bytearray([operation]) + data
        xor_key, shift = (
            b"\x33\x53\x93\x63\xa3\xc3\x35\x55\x95\x65\xa5\xc5\x36\x56\x96\x66",
            4,
        )
    else:
        xor_key, shift = operations[operation]

    data = xor_bytes(data, xor_key)

    print(data[:16].hex())
    data = rotate_op(data, shift)

    print(data[:16].hex())

    with open(fn + ".dec", "wb") as of:
        of.write(data)
