from io import BytesIO
from pathlib import Path
from struct import unpack
from sys import argv

import pefile  # type: ignore


def decrypt_container(data: bytes) -> bytes:
    MASK = 0xFFFFFFFFFFFFFFFF
    INIT_SEED = 0x7F23BBE38FA12345

    out = bytearray(data)
    seed = INIT_SEED

    for i in range(len(data)):
        seed ^= seed >> 0x0C
        seed ^= (seed << 0x19) & MASK
        seed ^= seed >> 0x1B
        seed &= MASK
        out[i] ^= seed & 0xFF

    return bytes(out)


if __name__ == "__main__":
    if len(argv) != 2:
        print("Usage: python extract_eggconsole_pac.py <pac_file>")
        exit(1)

    exe_file = Path(argv[1])
    pe = pefile.PE(exe_file, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )

    pac_offset = None
    pac_size = None
    pac = None
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:  # type: ignore
        name_entry = rsrc.directory.entries[0]
        if name_entry.struct.Name == 0xD24:
            if not hasattr(name_entry, "directory"):
                print("Unexpected leaf at name level")
                continue
            leaf = name_entry.directory.entries[0]
            if not hasattr(leaf, "data"):
                print("Unexpected directory at language level")
                continue
            pac_offset = leaf.data.struct.OffsetToData
            pac_size = leaf.data.struct.Size
            pac = pe.get_memory_mapped_image()[pac_offset : pac_offset + pac_size]

    if pac_offset is None or pac_size is None or pac is None:
        print("PAC resource not found.")
        exit(1)

    decrypted_pac = decrypt_container(pac)
    # with open(exe_file.stem + ".pac", "wb") as f:
    #     f.write(decrypted_pac)

    f = BytesIO(decrypted_pac)
    # Check for magic
    if f.read(4) != b"DPAC":
        print("Invalid PAC file (bad magic)")
        exit(1)
    version = unpack("<I", f.read(4))[0]
    if version != 1:
        print("Unsupported PAC version:", version)
        exit(1)
    num_files = unpack("<I", f.read(4))[0]
    file_entries = []
    for _ in range(num_files):
        name_len = unpack("<H", f.read(2))[0]
        name = f.read(name_len).decode("cp932")
        offset, size = unpack("<QQ4x", f.read(20))
        file_entries.append((name, offset, size))

    for name, offset, size in file_entries:
        f.seek(offset)
        data = f.read(size)
        out_path = exe_file.stem / Path(name)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as out_file:
            out_file.write(data)
        print(f"Extracted {name} to {out_path}")
