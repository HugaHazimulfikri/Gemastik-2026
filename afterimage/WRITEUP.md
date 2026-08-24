# `Afterimage` — Forensic

> 🏷️ **Challenge metadata**

|                  |                    |                |                        |
| ---------------- | ------------------ | -------------- | ---------------------- |
| 🏆 **Event**     | `Gemastik 2026`    | 📅 **Date**    | `2026-08-23`           |
| 🏷️ **Category** | `Forensic`         | 💯 **Points**  | `473`                  |
| 👤 **Author**    | `el es bebe stego merberto` | 🧑‍💻 **Team** | `DOSCOM`      |

---

### 📝 Deskripsi Soal

> **Description dari panitia:**
>
> There was an incident happening in one of our container in our main server. There were only few footprints and one file was stolen. Our Incident Response team with the Security Research decided to narrow down the search by dumping the only artifact related to the incident of the container.

**📎 Attachment:**

| File | Tipe | Ukuran |
|---|---|---|
| `mem.zip` -> `memory.lime` | zip | 1.2 KB |

**🔌 File info:**

```bash
memory.lime
```

---

### 🔍 Reconnaissance

> Langkah awal untuk memahami struktur & behavior challenge.

```bash
unzip -l mem.zip          # memory.lime, 64.203.104 byte
unzip mem.zip
file memory.lime          # data
```

Cek header LiME (Linux Memory Extractor):

```python
magic = 0x4c694d45   # "LiME"
version = 1
```
<img width="1488" height="500" alt="image" src="https://github.com/user-attachments/assets/19b7b4b8-c320-4a33-8733-a065b0c026ff" />

Ini dump **memori fisik**, bukan file image. Konsekuensinya penting dan nanti akan menggigit:
halaman virtual sebuah proses tidak berurutan di dump ini.

Cek isi kasar:

```bash
strings -a -n 10 memory.lime | grep -aiE "^Linux version|Debian |Alpine"
# GCC: (Debian 14.2.0-19) 14.2.0

strings -a -n 8 memory.lime | grep -aoiE "docker|containerd|runc" | sort | uniq -c
#  102 docker / 99 runc / 80 containerd
```
<img width="1468" height="699" alt="Tangkapan Layar 2026-08-23 pukul 20 47 58" src="https://github.com/user-attachments/assets/7815b018-c5b8-4a6b-b4c0-b0b2ccb2c92a" />

---

### 🧠 Merekonstruksi insiden dari scrollback terminal

Cari jejak eksfiltrasi:

```bash
strings -a -n 6 memory.lime | grep -aoiE "(base64 -d|memfd_create|ld\.so\.preload)"
```

Dua baris langsung menonjol: `base64 -d > /dev/shm/.pulse-x`.
<img width="892" height="769" alt="Tangkapan Layar 2026-08-23 pukul 20 59 39" src="https://github.com/user-attachments/assets/b1a1dd3d-51db-4ae3-b362-817f5c43fae6" />

Dengan mengambil konteks di sekitarnya, seluruh rangkaian serangan terbaca. Ketika kita memfilter
dump memori menggunakan pola string spesifik seperti `base64 -d`, `memfd_create`, dan
`ld.so.preload`, output yang muncul langsung memperlihatkan indikator utama dari teknik eksfiltrasi
dan persistensi penyerang:

* **`ld.so.preload`**: Muncul berulang kali karena penyerang mencoba memasang dynamic linker
  preload untuk memuat rootkit (`.so`), yang sayangnya sempat gagal dan memicu error berulang di
  memori.
* **`base64 -d`**: Menunjukkan perintah yang dipakai penyerang untuk mendekode payload yang
  dikirim secara terpotong-potong melalui variabel terminal.
* **`memfd_create`**: Menandakan teknik eksekusi *fileless* (tanpa menulis file fisik ke disk) yang
  digunakan untuk menjalankan payload berbahaya dan menyamar sebagai proses kernel `[kworker/u8:2]`.

Dari temuan inilah kita tahu bahwa meskipun penyerang mencoba membersihkan jejak menggunakan
`history -c`, buffer terminal (*afterimage*) di memori masih merekam seluruh rangkaian aksi mereka
dengan jelas.

Karena buffer scrollback terminal merekam seluruh interaksi secara utuh, kita tidak hanya menemukan
perintah eksekusinya saja, tetapi juga artefak data yang dikirim oleh penyerang. Jika kita telusuri
baris-baris teks di sekitar perintah `base64 -d` pada dump memori, terlihat jelas ada sisa string
Base64 yang ikut tertinggal (*afterimage*). Kita bisa mencarinya langsung di file memori:

```bash
strings -a memory.lime | grep "KEVt/"
```
Dari pencarian tersebut, terungkaplah string Base64 utuh yang menjadi muatan data curian penyerang:
```
KEVt/ztn6l1WUQBRFINKy4Jp/VQ8kzAn/cZ2MlHoZCUAOvRFumQ4KUESHqdXwjbmowc/3389i++Zwpxzav79dikwrqx6/XlyULlASA==
```

### 🧩 Blob Curian

Dari jejak terminal yang terekam tersebut, string berawalan `KEVt/` ini merupakan data yang
di-decode oleh penyerang. Ketika kita periksa lebih lanjut, teks Base64 tersebut menghasilkan 76
byte data acak (ciphertext) dengan entropi tinggi. Data inilah yang berisi file curian
(`/srv/app/flag.txt`) dan harus kita buka kuncinya. Untuk membuktikannya, kita dapat menjalankan
utilitas Python di terminal untuk mendekode string tersebut dan memverifikasi panjang biner
aslinya:

```bash
python3 -c 'import base64; b = base64.b64decode("KEVt/ztn6l1WUQBRFINKy4Jp/VQ8kzAn/cZ2MlHoZCUAOvRFumQ4KUESHqdXwjbmowc/3389i++Zwpxzav79dikwrqx6/XlyULlASA=="); print(len(b))'
```
<img width="1470" height="231" alt="Tangkapan Layar 2026-08-23 pukul 21 18 59" src="https://github.com/user-attachments/assets/26b15dcb-1221-4bb3-a71f-4e785fdfee16" />

### 🔑 Membedah Payload dan Menemukan Kunci

Setelah memastikan ukuran blob data curian valid sepanjang 76 byte, langkah berikutnya adalah
mengekstrak parameter kriptografi dari sisa payload di memori. Kita dapat melakukannya murni
menggunakan perintah terminal standar (`strings`, `grep`, `dd`, dan `xxd`).

**Langkah 1: Menemukan Lokasi Konstanta ChaCha20.** Pertama, cari alamat memori dari string
konstanta sigma `expand 32-byte k` yang menandakan algoritma ChaCha20:
```bash
strings -a -t x memory.lime | grep "expand 32-byte k"
```
<img width="856" height="143" alt="Tangkapan Layar 2026-08-23 pukul 21 20 22" src="https://github.com/user-attachments/assets/298211fb-0dc1-4f84-9861-0268d5805bac" />

Dari hasil di atas, string penanda tersebut ditemukan pada alamat `0x31699f0`.

**Langkah 2: Memindai Blok Kunci dan Nonce dengan Analisis Entropi.** Karena struktur memori fisik
tersebar dan perintah offset statis via `dd` tidak mengenai blok data biner yang tepat, kita
melakukan pemindaian lanjutan (entropy scanning) di sekitar area alamat `.rodata` tersebut untuk
menemukan blok data acak (kunci dan nonce) yang disimpan oleh compiler:
```bash
dd if=memory.lime bs=1 skip=$((0x31699f0 - 128)) count=128 2>/dev/null | xxd
```
<img width="689" height="240" alt="Tangkapan Layar 2026-08-23 pukul 21 20 56" src="https://github.com/user-attachments/assets/d084666d-536f-4949-a716-5fd2130591ea" />

<img width="777" height="431" alt="Tangkapan Layar 2026-08-23 pukul 21 30 31" src="https://github.com/user-attachments/assets/3c02e2c0-ac4d-48e0-9491-81ed721df3eb" />

**Hasil Ekstraksi Parameter.** Dari tabel heksadesimal yang tercetak di terminal, baris data biner
tepat di sebelum string konstanta tersebut memperlihatkan parameter kriptografi yang digunakan:

- Nonce (12-byte): `5aa2e1ef2bcc80868ad53417`
- Kunci (32-byte): `15d19593e44d3f39bf2fab5e52410d5af1cea024256bd44692a1d033356575c7`

---

### ⚔️ Dekripsi Akhir

Setelah mendapatkan parameter Kunci dan Nonce yang valid serta ciphertext berukuran 76 byte, tahap
terakhir adalah melakukan dekripsi menggunakan algoritma ChaCha20.

**Catatan Kritis RFC 8439.** Dalam standar RFC 8439, blok pertama (counter = 0) pada ChaCha20 secara
khusus dicadangkan untuk kunci autentikasi Poly1305. Karena ciphertext hasil eksfiltrasi ini
merupakan data murni tanpa tag Poly1305 dan menggunakan 12-byte nonce, proses dekripsi wajib dimulai
dari counter = 1. Jika menggunakan counter = 0, hasil dekripsinya akan berupa data sampah (garbage).

Solver lengkapnya ada di [`solve.py`](solve.py):

```python
import base64
from Crypto.Cipher import ChaCha20

def decrypt_afterimage_rfc8439():
    # 1. Parameter dari analisis memori CTF "Afterimage"
    key_hex = "15d19593e44d3f39bf2fab5e52410d5af1cea024256bd44692a1d033356575c7"
    nonce_hex = "5aa2e1ef2bcc80868ad53417"
    ciphertext_b64 = "KEVt/ztn6l1WUQBRFINKy4Jp/VQ8kzAn/cZ2MlHoZCUAOvRFumQ4KUESHqdXwjbmowc/3389i++Zwpxzav79dikwrqx6/XlyULlASA=="

    # 2. Konversi format data hex & base64 ke bytes
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = base64.b64decode(ciphertext_b64)

    # 3. Inisialisasi cipher ChaCha20 dengan 12-byte nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)

    # 4. Secara eksplisit geser counter ke 1 (RFC 8439)
    # Blok 0 (byte 0-63) dilewati, dekripsi dimulai dari blok 1 (byte ke-64)
    cipher.seek(1 * 64)

    try:
        # 5. Proses Dekripsi data
        plaintext = cipher.decrypt(ciphertext)

        # 6. Tampilkan hasil flag
        print("[+] Dekripsi berhasil dengan Counter = 1!")
        print(f"Plaintext Bytes: {plaintext}")
        print(f"\n[!] Flag Asli:\n{plaintext.decode('utf-8')}")

    except Exception as e:
        print(f"[-] Terjadi kesalahan saat dekripsi: {e}")

if __name__ == "__main__":
    decrypt_afterimage_rfc8439()
```

<img width="1268" height="802" alt="Tangkapan Layar 2026-08-23 pukul 21 32 38" src="https://github.com/user-attachments/assets/c48bbfd7-991a-4708-bc57-bd1932d0eec0" />

---

### 🚩 Flag

```
GEMASTIK19{794dee6920bbafb15b784d6c82ab41a1d8a459fa59e0fd0b6e1aed9bb0175504}
```

### 🤖 AI Chat

```
https://gemini.google.com/share/bf2f5c6af478?skid=37e536b0-ec51-4002-a23c-26c99229a76d
```
