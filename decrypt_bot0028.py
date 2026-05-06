from sys import argv


def decrypt_resource(data: bytes) -> bytes:
    size = len(data)
    seed = 0x25
    buffer = bytearray(size)

    v5 = seed & 0xFF
    v6 = seed & 0xFFFFFFFF
    v7 = (seed >> 3) & 7

    # --- Stage 1: variable rotate ---
    for i in range(size):
        b = data[i]

        # ROL1(b, v7)
        v9 = ((b << v7) | (b >> (8 - v7))) & 0xFF

        v7 = (b >> 3) & 7
        buffer[i] = v9

    # --- Stage 2: XOR chaining ---
    for i in range(size):
        v13 = buffer[i]
        buffer[i] ^= v5
        v5 = v13

    # --- Stage 3: PRNG XOR ---
    for i in range(size):
        v6 = ((v6 << 12) + 0x24D69) % 0xAE529

        # replicate the assembly's division/mul trick:
        keystream = ((v6 << 8) // 0xAE529) & 0xFF

        buffer[i] ^= keystream

    return bytes(buffer)


with open(argv[1], "rb") as f:
    encrypted_data = f.read()

decrypted_data = decrypt_resource(encrypted_data)
with open(argv[2] or "decrypted.bin", "wb") as f:
    f.write(decrypted_data)
