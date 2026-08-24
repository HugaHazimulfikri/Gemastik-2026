# `common-encoding` — crypto

> 🏷️ **Challenge metadata**

|                  |                    |                |                        |
| ---------------- | ------------------ | -------------- | ---------------------- |
| 🏆 **Event**     | `Gemastik 2026`    | 📅 **Date**    | `2026-08-23`           |
| 🏷️ **Category** | `crypto`           | 💯 **Points**  | `100`                  |
| 👤 **Author**    | `wondping0`        | 🧑‍💻 **Team** | `DOSCOM Zero Day Scholars` (sanzxcte)              |

---

### 📝 Deskripsi Soal

> **Description dari panitia:**
>
> Did you know basic encoding? Need deleting spaces? howd?

**📎 Attachment:**

| File | Tipe | Ukuran |
|---|---|---|
| `cipher.txt` | text | 701 B |

Format flag: `GEMASTIK19{...}`.

---

### 🔍 Karakteristik & Analisis Ciphertext

Berdasarkan pemeriksaan awal pada *ciphertext*, ditemukan aturan struktur sebagai berikut:

* **Marker Start & End:** Diawali dengan huruf `S` dan diakhiri dengan huruf `Z`.
* **Delimiter:** Pemisah antar blok data menggunakan string `DW`.
* **Format Data:** Di dalam setiap blok, hanya terdapat karakter `O` dan `H` yang merepresentasikan
  biner:
  * `O` = `1`
  * `H` = `0`
* **Alur Dekode:**
  1. Hilangkan *marker* `S` dan `Z`.
  2. Pecah (*split*) data berdasarkan delimiter `DW`.
  3. Konversikan setiap blok biner ke nilai desimal, lalu ke karakter ASCII.
  4. Hasil gabungan dari seluruh karakter tersebut membentuk sebuah string berformat **Hex**.
  5. Lakukan dekode sekali lagi dari Hex ke ASCII untuk mendapatkan *flag* akhir.

---

### ⚔️ Python Solver Script

Berikut adalah skrip otomatisasi ([`solve.py`](solve.py)) untuk melakukan *parsing* dan dekode
ciphertext secara instan:

```python
def solve_ctf():
    # Ciphertext yang diberikan
    ciphertext = "SOOHOHHDWOOHOOODWOOHOHHDWOOHOHODWOOHOHHDWOOHHOHHDWOOHOHHDWOOHHHODWOOHOHODWOOHHOODWOOHOHODWOOHOHHDWOOHOHHDWOOOHHODWOOHOHHDWOOHHHOHDWOOHHOODWOOHHHODWOOHHOODWOOOHHODWOOHOOODWOOHHHOHDWOOHOHODWOOHOHHDWOOHOHODWOOHOHODWOOHOHODWOOHOHHDWOOHOHHDWOOHHOOHDWOOHOHODWOOHHOHDWOOHHOHDWOOHHHODWOOHHOHDWOOHHHODWOOHOHODWOOHHOOHDWOOHOOODWOOHHOODWOOHOOODWOOHOHODWOOHOOHDWOOHHOHDWOOHOOHDWOOHHOHHDWOOHOOHDWOOOHHODWOOHOOODWOOHOHHDWOOHHOHDWOOHHOHHDWOOHOOHDWOOHHOODWOOHOOODWOOHHOHDWOOHOOODWOOOHHODWOOHOOODWOOHHHHDWOOHOOODWOOHOHHDWOOHOOHDWOOHHOOHDWOOHHOHDWOOHHOHHDWOOHOOHDWOOHOOHDWOOHOOHDWOOHHHOODWOOHOOHDWOOHHHODWOOHOOHDWOOHOOODWOOHOHODWOOHHOOHDWOOHOHHDWOOHOHHDWOOHHOODWOOHHHHDWOOHOOHDWOOHHOHODWOOHOOHDWOOHOOODWOOHOOODWOOHHOHHZ"

    # 1. Validasi Marker Start & End
    if not (ciphertext.startswith('S') and ciphertext.endswith('Z')):
        print("[-] Peringatan: Marker awal atau akhir tidak sesuai.")

    # Hilangkan huruf 'S' di awal dan 'Z' di akhir
    core_data = ciphertext[1:-1]

    # 2. Split berdasarkan delimiter "DW"
    blocks = core_data.split("DW")

    binary_chars = []

    # 3. Proses setiap blok (O = 1, H = 0)
    for block in blocks:
        if not block:
            continue
        # Ganti 'O' dengan '1' dan 'H' dengan '0'
        bin_str = block.replace('O', '1').replace('H', '0')

        # Konversi string biner ke integer, lalu ke karakter ASCII
        decimal_val = int(bin_str, 2)
        binary_chars.append(chr(decimal_val))

    # Gabungkan menjadi string Hex awal
    hex_string = "".join(binary_chars)
    print(f"[+] Hex String: {hex_string}")

    # 4. Decode dari Hex ke string teks asli (flag)
    try:
        flag = bytes.fromhex(hex_string).decode('utf-8')
        print(f"[+] Flag Berhasil Didapatkan: {flag}")
    except Exception as e:
        print(f"[-] Gagal melakukan decode hex ke ASCII: {e}")

if __name__ == "__main__":
    solve_ctf()
```

**Bukti Hasil Eksekusi.** Saat skrip dijalankan pada lingkungan terminal, proses parsing berhasil
menerjemahkan seluruh blok biner menjadi representasi hexadecimal, yang kemudian didecode kembali
menjadi plaintext bersih:

<img width="1468" height="867" alt="Tangkapan Layar 2026-08-23 pukul 22 38 52" src="https://github.com/user-attachments/assets/6236946f-73b8-4244-af63-089bb3524ec1" />

```
[+] Hex String: 47454d415354494b31397b5455544f5221215f7375626d69742d63727970746f2d666c61675f44306e677d
[+] Flag Berhasil Didapatkan: GEMASTIK19{TUTOR!!_submit-crypto-flag_D0ng}
```

---

### 🚩 Flag

```
GEMASTIK19{TUTOR!!_submit-crypto-flag_D0ng}
```

### 🤖 AI Chat

```
https://share.gemini.google/MMJvo7usWfKj
```
