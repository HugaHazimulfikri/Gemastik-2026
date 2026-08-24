#!/usr/bin/env python3
"""
wraith - GEMASTIK XIX 2026 Reverse (469)

Binary C statis dan stripped yang berisi VM bytecode. Program VM-nya disimpan
terenkripsi XOR dengan keystream splitmix64, lalu dijalankan interpreter
3 byte per instruksi.

Setelah didekripsi, programnya ternyata jaringan Feistel 24 ronde di atas empat
register 64-bit, dan SETIAP operasinya invertibel:

    ADD r,r     -> kurangi
    MUL r,K     -> kali invers modular (semua K ganjil)
    ROL r,n     -> ROR r,n
    XOR r,r     -> XOR lagi
    MOV (blok)  -> permutasi siklik, tinggal dibalik
    ADDK r,i    -> kurangi konstanta

Jadi tidak perlu brute force maupun SMT solver. Ambil nilai target dari
instruksi CHECK, jalankan seluruh program mundur, dan input aslinya keluar.

Jalankan dari folder yang berisi binary `wraith`.
"""
import struct
import subprocess
import sys

BIN = "wraith"
M64 = (1 << 64) - 1
GOLD = 0x9E3779B97F4A7C15
SM_C1 = 0xBF58476D1CE4E5B9
SM_C2 = 0x94D049BB133111EB
SM_ADD = 0x3C6EF372FE94F82A
KS_END = 0xC83888AD2A34A5ED

# alamat hasil analisis statis (.rodata VA 0x487000 -> file 0x87000)
VA_MULTAB = 0x4891C0        # 24 pengali u64
VA_TARGET = 0x489288        # 4 nilai target u64
VA_SEED_A = 0x4892B0        # seed keystream
VA_SEED_B = 0x4892B8
VA_CODE = 0x4892C0          # bytecode terenkripsi
CODE_LEN = 961
KS_BITS = 0x1E08            # 7688 bit = 961 byte


def fo(va):
    return va - 0x487000 + 0x87000


def rol(v, n):
    n &= 63
    return ((v << n) | (v >> (64 - n))) & M64 if n else v


def ror(v, n):
    return rol(v, 64 - (n & 63)) if (n & 63) else v


def splitmix_final(z):
    z = ((z >> 30) ^ z) * SM_C1 & M64
    z = ((z >> 27) ^ z) * SM_C2 & M64
    return (z >> 31) ^ z


def decrypt_bytecode(blob, seed_a, seed_b):
    """Keystream splitmix64 yang dianyam dengan dua state tambahan."""
    code = bytearray(blob)
    x8, xs, state = seed_a, seed_b, 0
    bits, pos = KS_BITS, 0
    while True:
        state = (state + GOLD) & M64
        t = ((state >> 30) ^ state) * SM_C1 & M64
        t = ((t >> 27) ^ t) * SM_C2 & M64
        saved = t
        a = t ^ xs
        xs = rol(xs, 29)
        a ^= saved >> 31
        a = (a + x8) & M64
        xs ^= a
        a = rol(a, 17)
        x8 = a
        k = (xs + a) & M64
        c = 0
        while c < 64 and c < bits:
            code[pos] ^= (k >> c) & 0xFF
            pos += 1
            c += 8
        if c >= bits:
            break
        bits -= 64
        if state == KS_END:
            break
    return bytes(code)


def main():
    try:
        data = open(BIN, "rb").read()
    except FileNotFoundError:
        sys.exit(f"[-] {BIN} tidak ada")
    print(f"[*] Memuat {BIN} ({len(data):,} byte)")

    seed_a = struct.unpack("<Q", data[fo(VA_SEED_A):fo(VA_SEED_A) + 8])[0]
    seed_b = struct.unpack("<Q", data[fo(VA_SEED_B):fo(VA_SEED_B) + 8])[0]
    code = decrypt_bytecode(data[fo(VA_CODE):fo(VA_CODE) + CODE_LEN], seed_a, seed_b)

    prog = [(code[i], code[i + 1], code[i + 2]) for i in range(0, len(code) - 2, 3)]
    valid = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x99}
    if not all(op in valid for op, _, _ in prog):
        sys.exit("[-] dekripsi bytecode gagal, ada opcode tak dikenal")
    print(f"[+] Bytecode terdekripsi: {len(prog)} instruksi, semua opcode valid")

    mul = list(struct.unpack("<24Q", data[fo(VA_MULTAB):fo(VA_MULTAB) + 24 * 8]))
    target = list(struct.unpack("<4Q", data[fo(VA_TARGET):fo(VA_TARGET) + 32]))
    if any(m % 2 == 0 for m in mul):
        sys.exit("[-] ada pengali genap, tidak invertibel")
    minv = [pow(m, -1, 1 << 64) for m in mul]
    konst = [splitmix_final((i * GOLD + SM_ADD) & M64) for i in range(24)]
    print(f"[+] 24 pengali (semua ganjil), 24 konstanta ronde, 4 nilai target")

    # ---- jalankan mundur dari target -----------------------------------
    r = list(target)
    for i in reversed(range(24)):
        r[0] = (r[0] - konst[i]) & M64                 # ADDK
        r[1], r[2], r[3] = r[3], r[1], r[2]            # balik permutasi MOV
        r[3] ^= r[2]
        r[3] = ror(r[3], 37)
        r[2] = r[2] * minv[i] & M64
        r[2] = (r[2] - r[3]) & M64
        r[1] ^= r[0]
        r[1] = ror(r[1], 13)
        r[0] = r[0] * minv[i] & M64
        r[0] = (r[0] - r[1]) & M64
    print(f"[+] Input dipulihkan: {[hex(x) for x in r]}")

    # ---- verifikasi dengan menjalankan maju -----------------------------
    f = list(r)
    for i in range(24):
        f[0] = (f[0] + f[1]) & M64
        f[0] = f[0] * mul[i] & M64
        f[1] = rol(f[1], 13) ^ f[0]
        f[2] = (f[2] + f[3]) & M64
        f[2] = f[2] * mul[i] & M64
        f[3] = rol(f[3], 37) ^ f[2]
        f[1], f[2], f[3] = f[2], f[3], f[1]
        f[0] = (f[0] + konst[i]) & M64
    if f != target:
        sys.exit("[-] verifikasi maju gagal, inversi salah")
    print("[+] Verifikasi maju cocok dengan target")

    inner = b"".join(struct.pack("<Q", x) for x in r)
    flag = "GEMASTIK19{" + inner.decode("latin1") + "}"
    print(f"[+] FLAG: {flag}")

    # ---- verifikasi akhir ke binary aslinya -----------------------------
    res = subprocess.run(["./" + BIN], input=flag.encode() + b"\n",
                         capture_output=True, timeout=60)
    out = (res.stdout + res.stderr).decode(errors="replace").strip()
    print(f"[+] Verifikasi ./{BIN}: {out}")


if __name__ == "__main__":
    main()
