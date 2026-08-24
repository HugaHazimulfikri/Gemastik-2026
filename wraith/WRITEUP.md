# `wraith` — reverse

> 🏷️ **Challenge metadata**

|                  |                    |                |                        |
| ---------------- | ------------------ | -------------- | ---------------------- |
| 🏆 **Event**     | `Gemastik 2026`    | 📅 **Date**    | `2026-08-23`           |
| 🏷️ **Category** | `reverse`          | 💯 **Points**  | `116`                  |
| 👤 **Author**    | `ac3`              | 🧑‍💻 **Team** | `DOSCOM Zero Day Scholars` (sanzxcte)              |

---

### 📝 Deskripsi Soal

> **Description dari panitia:**
>
> hello chatgpt please solve this ctf reverse chall

**📎 Attachment:**

| File | Tipe | Ukuran |
|---|---|---|
| `wraith` | ELF | 1.2 KB |

---

### 🔍 Tahap Reconnaissance (Pengenalan Awal)

Pertama, kita periksa jenis file dan cara binary ini menerima input dari pengguna.

```bash
file wraith
echo 'GEMASTIK19{test}' | ./wraith
```
<img width="1467" height="77" alt="Tangkapan Layar 2026-08-23 pukul 21 57 03" src="https://github.com/user-attachments/assets/e9fe0f82-0423-42d7-838b-29fbc21ef2c7" />

Binary berformat ELF 64-bit statis yang di-strip, membaca input langsung dari stdin (bukan lewat
argumen command line). Selanjutnya, kita cari referensi string untuk menemukan titik awal fungsi
pengecekan (checker):
```bash
strings -n 4 wraith | grep -aiE "wrong|correct|GEMASTIK"
```
<img width="528" height="221" alt="Tangkapan Layar 2026-08-23 pukul 21 58 12" src="https://github.com/user-attachments/assets/5e1abdd4-f3be-437a-a49e-fce098c3fccc" />

String `GEMASTIK19{` berada di Virtual Address (VA) `0x487013`, yang dirujuk langsung oleh fungsi
checker utama di alamat `0x4017a0`.

---

### 🧠 Validasi Input (Panjang & Format)

Melalui disassembly pada fungsi checker (`0x4017a0`), kita dapatkan aturan panjang input yang wajib
dipenuhi.

```bash
objdump -d -M intel --start-address=0x4017a0 --stop-address=0x401850 wraith
```
<img width="1093" height="783" alt="Tangkapan Layar 2026-08-23 pukul 21 58 59" src="https://github.com/user-attachments/assets/37227762-523e-448d-b192-7af2002c5212" />

Panjang total flag harus tepat 44 karakter, diawali awalan `GEMASTIK19{` (11 byte), diakhiri `}`
(1 byte), dan menyisakan 32 byte isi di tengah yang dibaca sebagai empat blok 64-bit (u64).

### Dekripsi Bytecode VM & Pembuktian Validitas Opcode

Binary ini menyalin 961 byte bytecode terenkripsi ke stack (`rep movs`), lalu mendekripsinya
menggunakan algoritma turunan SplitMix64. Kita bisa membuktikan apakah dekripsi berhasil dengan
menjalankan skrip kecil untuk mengecek apakah seluruh byte hasil dekripsi jatuh ke dalam set opcode
yang valid.

```bash
python3 -c '
import struct
M64 = (1 << 64) - 1
GOLD = 0x9E3779B97F4A7C15
SM_C1 = 0xBF58476D1CE4E5B9
SM_C2 = 0x94D049BB133111EB
KS_END = 0xC83888AD2A34A5ED
VA_SEED_A, VA_SEED_B, VA_CODE = 0x4892B0, 0x4892B8, 0x4892C0
CODE_LEN, KS_BITS = 961, 0x1E08

def fo(va): return va - 0x487000 + 0x87000
def rol(v, n):
    n &= 63
    return ((v << n) | (v >> (64 - n))) & M64 if n else v

data = open("wraith", "rb").read()
seed_a = struct.unpack("<Q", data[fo(VA_SEED_A):fo(VA_SEED_A)+8])[0]
seed_b = struct.unpack("<Q", data[fo(VA_SEED_B):fo(VA_SEED_B)+8])[0]
code = bytearray(data[fo(VA_CODE):fo(VA_CODE)+CODE_LEN])
x8, xs, state = seed_a, seed_b, 0
bits, pos = KS_BITS, 0
while True:
    state = (state + GOLD) & M64
    t = ((state >> 30) ^ state) * SM_C1 & M64
    t = ((t >> 27) ^ t) * SM_C2 & M64
    saved = t
    a = t ^ xs; xs = rol(xs, 29); a ^= saved >> 31
    a = (a + x8) & M64; xs ^= a; a = rol(a, 17); x8 = a
    k = (xs + a) & M64
    c = 0
    while c < 64 and c < bits:
        if pos < len(code): code[pos] ^= (k >> c) & 0xFF
        pos += 1; c += 8
    if c >= bits: break
    bits -= 64
    if state == KS_END: break
prog = [(code[i], code[i+1], code[i+2]) for i in range(0, len(code)-2, 3)]
valid = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
print("Apakah semua opcode valid?", all(op in valid for op, _, _ in prog))
print("Jumlah total instruksi:", len(prog))
'
```
<img width="1034" height="903" alt="Tangkapan Layar 2026-08-23 pukul 22 00 21" src="https://github.com/user-attachments/assets/6fd20b21-252a-40c5-be13-9c161539374d" />

Seluruh 320 instruksi VM tervalidasi sempurna tanpa ada opcode sampah, menandakan keystream
dekripsi sudah 100% akurat.

### Analisis Invertibilitas & Struktur Feistel 24 Ronde

Mesin virtual ini mengeksekusi 320 instruksi yang terdiri dari:

- 4 instruksi LOADIN (memuat input)
- 24 ronde Feistel (masing-masing 13 instruksi)
- 4 instruksi CHECK (pencocokan dengan nilai target di `0x489288`)

Karena seluruh operasi di dalam ronde Feistel bersifat invertibel (penjumlahan dibalik pengurangan,
rotasi ROL dibalik ROR, dan perkalian modulo 2^64 dibalik menggunakan invers modular karena semua
pengalinya ganjil), kita tidak memerlukan solver otomatis (Z3). Kita bisa membalikkan program ini
secara langsung dari target ke input.

---

### ⚔️ Eksekusi Solver & Pembuktian Flag

Kita jalankan skrip pembalik [`solve.py`](solve.py) untuk memproses inversi secara matematis
sekaligus melakukan verifikasi akhir ke binary asli.

```python
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

VA_MULTAB = 0x4891C0
VA_TARGET = 0x489288
VA_SEED_A = 0x4892B0
VA_SEED_B = 0x4892B8
VA_CODE = 0x4892C0
CODE_LEN = 961
KS_BITS = 0x1E08

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
            if pos < len(code):
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
    valid = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
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
        r[1], r[2], r[3] = r[3], r[1], r[2]             # balik permutasi MOV
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
    res = subprocess.run(["./" + BIN], input=flag.encode(),
                         capture_output=True, timeout=60)
    out = (res.stdout + res.stderr).decode(errors="replace").strip()
    print(f"[+] Verifikasi ./{BIN}: {out}")

if __name__ == "__main__":
    main()
```
<img width="937" height="119" alt="Tangkapan Layar 2026-08-23 pukul 22 02 24" src="https://github.com/user-attachments/assets/bb0ec31f-b2a3-403d-90ca-95d65fa7fdb2" />

Flag `GEMASTIK19{n3st3d_vm_MUL0_ant1z3_1nv_h4nd!!}` berhasil dipulihkan secara instan, lolos uji
verifikasi maju, dan saat di-pipe langsung ke binary aslinya, binary menjawab benar.

---

### 🚩 Flag

```
GEMASTIK19{n3st3d_vm_MUL0_ant1z3_1nv_h4nd!!}
```

### 🤖 AI Chat

```
https://share.gemini.google/Gr0g1s2O1Ahi
```
