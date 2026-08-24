#!/usr/bin/env python3
"""
Afterimage - GEMASTIK XIX 2026 Forensics (499)

Dump memori LiME dari container Debian yang dibobol. Penyerang menjalankan
payload fileless (memfd_create + execv), membaca /srv/app/flag.txt, meng-
enkripsinya dengan ChaCha20, lalu mencetak hasilnya sebagai base64 di terminal.

Semua bahan tertinggal di memori:
  - baris base64 hasil eksfiltrasi   (di scrollback terminal)
  - kunci 32 byte + nonce 12 byte    (di .data payload, tepat sebelum .comment)

Jalankan dari folder yang berisi memory.lime.
"""
import base64
import re
import struct
import sys

MEM = "memory.lime"
KNOWN = b"GEMASTIK19{"          # verifikator: plaintext harus diawali ini


# --------------------------------------------------------------------------
# ChaCha20 (RFC 8439) - counter 32-bit, nonce 96-bit
# --------------------------------------------------------------------------
def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] ^= x[a]; x[d] = _rotl(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] ^= x[c]; x[b] = _rotl(x[b], 7)


def _block(key, counter, nonce):
    state = ([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
             + list(struct.unpack("<8I", key))
             + [counter]
             + list(struct.unpack("<3I", nonce)))
    x = state[:]
    for _ in range(10):
        _qr(x, 0, 4, 8, 12);  _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13);  _qr(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(x, state)])


def chacha20(key, nonce, data, counter=1):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


# --------------------------------------------------------------------------
def _entropy(b):
    import collections, math
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def candidate_blobs(mem):
    """Semua base64 di memori yang decode-nya berupa data biner acak.

    Payload penyerang juga dikirim lewat base64, tapi isinya ELF yang penuh byte
    nol, jadi entropinya rendah. Ciphertext ChaCha20 entropinya mendekati 8.
    """
    seen = set()
    for m in re.finditer(rb"[A-Za-z0-9+/]{60,400}={0,2}", mem):
        raw = m.group(0)
        if raw in seen:
            continue
        seen.add(raw)
        try:
            blob = base64.b64decode(raw, validate=True)
        except Exception:
            continue
        if 32 <= len(blob) <= 300 and _entropy(blob) > 5.0 and blob.count(0) < len(blob) * 0.1:
            yield raw.decode(), blob


def candidate_keys(mem):
    """Kunci 32 byte dan nonce 12 byte berada 0x20 dan 0x40 byte sebelum
    string .comment milik payload."""
    for m in re.finditer(rb"\x00GCC: \(Debian", mem):
        i = m.start()
        if i >= 0x40:
            yield mem[i - 0x20:i], mem[i - 0x40:i - 0x34], i


def main():
    try:
        mem = open(MEM, "rb").read()
    except FileNotFoundError:
        sys.exit(f"[-] {MEM} tidak ada. Ekstrak dulu: unzip mem.zip")
    print(f"[*] Memuat {MEM} ({len(mem):,} byte)")

    print("[*] Mengumpulkan kandidat blob base64 dan kunci ...")
    blobs = list(candidate_blobs(mem))
    keys = list(candidate_keys(mem))
    print(f"[+] {len(blobs)} kandidat blob, {len(keys)} kandidat kunci")

    hit = None
    for b64, blob in blobs:
        for key, nonce, at in keys:
            if chacha20(key, nonce, blob).startswith(KNOWN):
                hit = (b64, blob, key, nonce, at)
                break
        if hit:
            break
    if hit is None:
        sys.exit("[-] tidak ada kombinasi blob/kunci yang menghasilkan prefiks flag")

    b64, blob, key, nonce, at = hit
    print(f"[+] blob   : {len(blob)} byte")
    print(f"[+] base64 : {b64}")
    print(f"[+] anchor : .comment @ {at:#x}")
    print(f"[+] key    : {key.hex()}")
    print(f"[+] nonce  : {nonce.hex()}")

    flag = chacha20(key, nonce, blob, counter=1).decode()
    print(f"[+] FLAG  : {flag}")


if __name__ == "__main__":
    main()
