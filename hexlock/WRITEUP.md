# 🏁 CTF Writeup - `GEMASTIK XIX 2026 - Keamanan Siber (Penyisihan)`

Writeup challenge **`hexlock`**.

---

# `hexlock` - reverse

|                  |                          |                |                                     |
| ---------------- | ------------------------ | -------------- | ----------------------------------- |
| 🏆 **Event**     | `GEMASTIK XIX 2026`      | 📅 **Date**    | `2026-08-24`                        |
| 🏷️ **Category** | `reverse`                | 💯 **Points**  | `500`                               |
| ⭐ **Difficulty** | ★★★★☆                    | 👤 **Author**  | `wondping0`                         |
| 🧑‍💻 **Team**    | `<isi nama tim>`         | 🛠️ **Tools**  | `objdump, gdb, pycryptodome`        |
| 🤖 **AI Source** | https://share.gemini.google/KGVvD7Uw2ofF | 🧩 **Solver** | [`hexlock-solved.py`](hexlock-solved.py) |
| 🔖 **Tags**      | `#golang` `#garble` `#anti-debug` `#aes-gcm` | | |

---

### 📝 Deskripsi Soal

> Line to codes? how to use: `./hexlock 'GEMASTIK19{...}'`
>
> Author: wondping0

Attachment cuma satu file: `hexlock` (ELF 64-bit, statis, stripped, ~1.5 MB).

Jadi ini flag checker: kasih tebakan flag lewat argumen, dia jawab `Correct!` atau `Wrong.`.

![Modal soal hexlock](img/01-soal.png)

---

### 🔍 Reconnaissance

Coba jalanin dulu, terus intip binarynya:

```bash
$ file hexlock
hexlock: ELF 64-bit LSB executable, x86-64, statically linked, stripped

$ echo 'GEMASTIK19{test}' | ./hexlock
Wrong.

$ strings -n 8 hexlock | grep -aoE "runtime\.|GCC:" | head
GCC: (Ubuntu ...)          # ada runtime.* juga -> ini binary Go

$ strings hexlock | grep -aoE "main\.[A-Za-z_]+" | head
                           # kosong

$ readelf -S hexlock | grep gopclntab
  [ 6] .gopclntab  PROGBITS  00000000004fbc60 ...
```

![Recon hexlock](img/02-recon.png)

Yang aku catat:

- Ini binary **Go**, statis dan stripped, ukuran ~1.5 MB. Ada `.gopclntab` (tabel simbol Go),
  tapi `main.*` sama versi `go1.x` kosong di strings. Curiga di-obfuscate.
- Waktu aku parse `.gopclntab` manual, magic di `0xfbc60` isinya `0x831bae3e`, bukan magic Go mana
  pun. Kelihatan sengaja dipatch. Tapi `nfunc = 1915` dan `textStart = 0x401000` cocok dengan VA
  `.text`, jadi layoutnya masih standar. Dari 1915 fungsi cuma 383 yang masih punya nama, sisanya
  `nameOff = 0`. Nama paket teracak. Ini ciri khas **garble**.
- Di daftar fungsi yang tersisa ada method `.Seal` (berarti ada AEAD/kripto) dan tipe-tipe
  `debug/elf` (berarti program baca file ELF, kemungkinan dirinya sendiri).

---

### 🧠 Analisis

**Nyari fungsi utama.** Nama `main.main` udah hilang, jadi aku lewat string. Cari `Wrong.` dan
`Correct!` di `.rodata`, terus karena string Go direferensi lewat header `{ptr, len}`, aku cari
pointer 8-byte yang nunjuk ke alamat string itu. Ketemu header `Wrong` di `0x4f7c90` dan `Correct`
di `0x4f7c80`. Grep disassembly buat `lea` ke header itu, mendarat di `0x4ad074`/`0x4ad0e3`, dan
fungsi induknya mulai di `0x4ace40`.

Alur checker-nya:

```
panjang input harus 44  (GEMASTIK19{ + 32 char isi + })
call 0x4acba0    -> hasilnya 16 byte (kunci AES)
call 0x4acd40    -> Seal(input) -> blob
cmp [0x56f498]   -> cek panjang
loop: or esi, buf[i] ^ target[i]   -> constant-time compare vs blob 66 byte di 0x56f490
```

Di dalam `0x4acd40`: `aes.NewCipher` (key 16 byte) lalu `NewGCM` (nonce 12, tag 16) lalu
`AEAD.Seal(input)`. Jadi checkernya: **`AES-128-GCM Seal(input) == blob 66 byte`**. Karena output
GCM = panjang input + 16 byte tag, dan blob-nya 66 byte, berarti **panjang flag = 50**.

Bahan yang aku kumpulin:
- nonce (statis di `0x567148`): `194b00b0922d969e007055a4`
- blob pembanding (header `{ptr,len}` di `0x56f490`): 66 byte
- key: dihitung runtime, jadi aku ambil lewat gdb breakpoint di `0x4acd77`

**Ini bagian yang bikin mentok.** Key hasil gdb dipakai buat `decrypt_and_verify`, hasilnya `MAC
check failed`. Ternyata ada **dua proteksi** di fungsi derivasi key `0x4acba0`:

1. **Anti-debug**: baca `/proc/self/status`, cari `TracerPid`. Kalau ketahuan lagi di-debug,
   `keymat[5] ^= 0x11`. Jadi key hasil gdb selalu salah satu byte.
2. **Self-integrity**: baca `/proc/self/exe`, hash binary-nya sendiri ikut jadi bahan key. Jadi
   nge-patch binary juga bikin key meleset total.

Buntu dua arah: pakai debugger key dirusak, patch binary hash berubah.

**Celahnya** ada di loop pencampuran key di `0x4acc8c`:

```
key[i] = rol(tabel[i] ^ keymat[i], 3) ^ hash_exe[i]
```

Semua operasinya **per-byte, indeks ke indeks, tanpa difusi**. Artinya korupsi `keymat[5]` dari
anti-debug cuma merusak **satu byte** di key akhir, sisanya tetap bener. Nilai byte yang benar
nggak bisa ditebak langsung (`^ 0x11` gagal karena kena `rol 3` dan penggabungan hash), tapi ruang
carinya kecil banget.

Jadi tinggal **brute-force 16 posisi × 256 nilai = 4096 kombinasi**, dan pakai **tag GCM sebagai
oracle**: `decrypt_and_verify` cuma lolos kalau key-nya bener.

---

### ⚔️ Exploitation

Solver lengkapnya di [`hexlock-solved.py`](hexlock-solved.py), jalanin dari folder yang ada
`./hexlock`-nya:

```bash
$ python3 hexlock-solved.py
```

Inti alurnya: baca nonce + blob langsung dari binary (VA ke file offset), ambil key terkorupsi via
gdb, brute-force 4096 kombinasi, verifikasi tiap kandidat pakai tag GCM, terakhir cek ke binary
aslinya.

```python
# nonce & blob dibaca dari binary, bukan dihardcode
nonce = binary[va_to_file(0x567148):][:12]
ptr, ln = struct(header di 0x56f490)                 # {ptr, len}
blob = binary[va_to_file(ptr):][:ln]                 # 66 byte, flag = ln - 16 = 50

# key dari gdb -- INI UDAH TERKORUPSI 1 byte gara-gara anti-debug
base_key = gdb_dump(breakpoint 0x4acd77, "x/16bx $rax")

# brute-force 16 posisi x 256, tag GCM yang mutusin
for pos in range(16):
    for b in range(256):
        base_key[pos] = b
        try:
            flag = AES.new(bytes(base_key), AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
            # ketemu
        except ValueError:
            continue
```

![Solver jalan sampai flag keluar](img/03-flag.png)

<details>
<summary>Log lengkap</summary>

```text
[*] Menjalankan GDB untuk mengambil base key...
[+] Base key dari GDB: 7f8a720509d6db11515d302c2695808a
    [CATATAN PENTING: Kunci di atas UDAH TERKORUPSI karena mekanisme anti-debug / TracerPid]
[*] Memulai brute-force 4096 kombinasi key untuk verifikasi GCM...
[+] Kunci valid ditemukan! Posisi byte ke-5 diubah ke 0x5e
[+] Flag berhasil didekripsi: GEMASTIK19{6_sh4rd5_r34ss3mbl3_th3_g0ph3r5_s3cr3t}
[*] Melakukan verifikasi otomatis dengan mengeksekusi binary...
[+] Output biner:
Correct!
[SUKSES] Flag terverifikasi 100% BENAR oleh program asli!
```

Byte ke-5 key: dari gdb `0xd6`, yang bener `0x5e`. Key asli: `7f8a7205095edb11515d302c2695808a`.
</details>

---

### 🚩 Flag

```
GEMASTIK19{6_sh4rd5_r34ss3mbl3_th3_g0ph3r5_s3cr3t}
```

---

### 📒 Catatan

- Tag AES-GCM itu oracle brute-force yang enak banget. Begitu ruang carinya kecil (di sini cuma
  4096), nggak perlu ngerti transformasi key-nya sama sekali, tinggal coba semua dan biarin tag
  yang mutusin.
- Binary Go yang di-garble bikin tool otomatis (GoReSym, redress) gagal karena magic pclntab
  dipatch. Tapi layoutnya masih standar, jadi bisa diparse manual.
- Anti-debug + self-integrity itu kombinasi yang saling nutup: debug bikin key rusak, patch bikin
  hash rusak. Yang nyelametin justru kelemahan desainnya, mixing key-nya per-byte tanpa difusi,
  jadi korupsinya cuma kena 1 byte.
- Sempat mikir key hasil gdb salah karena hash `/proc/self/exe` berubah waktu di-debug, tapi itu
  keliru. Isi file binary nggak berubah cuma gara-gara di-debug, jadi hash-nya sama. Yang bikin
  gagal itu karena korupsi kena `keymat[5]` duluan, baru lewat `xor tabel[5]` sama `rol 3`, jadi
  selisih `0x11` di input nggak muncul sebagai selisih `0x11` di output.
