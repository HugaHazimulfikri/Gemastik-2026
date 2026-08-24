# 🏁 CTF Writeup - `GEMASTIK XIX 2026 - Keamanan Siber (Penyisihan)`

Writeup challenge **`Cinder`**.

---

# `Cinder` - forensics

|                  |                          |                |                                     |
| ---------------- | ------------------------ | -------------- | ----------------------------------- |
| 🏆 **Event**     | `GEMASTIK XIX 2026`      | 📅 **Date**    | `2026-08-24`                        |
| 🏷️ **Category** | `forensics`              | 💯 **Points**  | `100`                               |
| ⭐ **Difficulty** | ★★☆☆☆                    | 👤 **Author**  | `aodreamer`                         |
| 🧑‍💻 **Team**    | `DOSCOM Zero Day Scholars` (nexsus404)         | 🛠️ **Tools**  | `python (sqlite3, pycryptodome)`    |
| 🤖 **AI Source** | https://share.gemini.google/qwuktsUlIDg9 | 🧩 **Solver** | [`Cinder-solved.py`](Cinder-solved.py) |
| 🔖 **Tags**      | `#sqlite` `#wal` `#android` `#aes-gcm` `#protobuf` | | |

---

### 📝 Deskripsi Soal

> A phone seized during a data leak investigation. All that came back is one chat app's extracted
> data directory, and nothing in it looks interesting at first.
>
> Author: aodreamer

Attachment: `cinder_extract.zip`, isinya folder sandbox aplikasi Android `com.example.cinder`.

![Modal soal Cinder](img/01-soal.png)

---

### 🔍 Reconnaissance

Struktur handout-nya:

```
com.example.cinder/
  databases/     chat.db (1536 B), chat.db-wal (5392 B), chat.db-shm (32768 B)
  files/         avatars/me.png (8 byte), avatars/.nomedia
  shared_prefs/  secure_prefs.xml
```

Ada file `-wal` dan `-shm` nemplok di sebelah `.db`-nya, jadi database ini pakai mode **WAL**
(Write-Ahead Log). Ini penting: WAL sering nyimpen jejak transaksi lama, termasuk data yang udah
dihapus tapi belum di-checkpoint balik ke db utama.

`me.png` cuma 8 byte, pas di-xxd isinya signature PNG doang tanpa data. Umpan.

`secure_prefs.xml` ngasih semua bahan kripto terang-terangan:

```xml
<string name="install_key">zFQ9GVudkfiHhytpG1zAl2B+DHLhE650mzYFCL+pqSI=</string>
<string name="kdf_salt">5n581xQBvjFW5FFDwj2stw==</string>
<int    name="kdf_iters" value="120000" />
<string name="msg_cipher">AES-256-GCM</string>
<string name="aead_aad">thread:rowid</string>
```

Dan ada `CASE_NOTE.md` yang bilang *"Work on a copy; keep the originals intact."*

![Recon Cinder](img/02-recon.png)

---

### 🧠 Analisis

**Jebakan pertama: jangan buka chat.db langsung.** Saya sempat buka `chat.db` pakai modul sqlite3
Python, dan file `chat.db-wal`-nya langsung ilang. Ternyata SQLite otomatis nge-checkpoint pas
database dibuka, isi WAL disalin ke db utama terus file WAL-nya dihapus. Untung saya kerjain di
salinan. Jadi peringatan "work on a copy" di case note itu beneran teknis, bukan basa-basi.

**Struktur pesan.** Tabel `messages` isinya 4 baris, kolom `body`-nya BLOB. Pas diintip ternyata
protobuf sederhana, semua wire type 2:

| Field | Isi |
|---|---|
| 1 | nama pengirim |
| 2 | nonce (12 byte) |
| 3 | ciphertext |
| 4 | tag GCM (16 byte) |

**Kuncinya.** `install_key` mentah nggak jalan buat AES-256. Yang bener diturunin dulu:

```
key = pbkdf2_hmac("sha256", b64decode(install_key), b64decode(kdf_salt), 120000, 32)
```

**AAD-nya template.** `"thread:rowid"` di prefs itu bukan literal, tapi template dua placeholder.
Saya coba beberapa varian dan biarin tag GCM yang mutusin, yang lolos ternyata `f"{thread}:{rowid}"`,
misalnya `family:1`.

Dengan itu 4 pesan kebuka, tapi isinya biasa aja (beli galon, resi paket). Di tabel `drafts` ada
`GEMASTIK{th1s_dr4ft_n0t3_1s_4_d3c0y}`, tapi itu umpan, formatnya `GEMASTIK{` bukan `GEMASTIK19{`
dan catatannya sendiri bilang "belum bener".

**WAL-nya yang jadi kunci.** Saya parse header WAL-nya: page size 512, jadi tiap frame 536 byte, dan
`(5392 - 32) / 536 = 10` pas. Dari field `dbsize` tiap frame, frame 4 dan frame 9 nilainya 6
(commit), sisanya 0. Berarti ada **dua transaksi**. SQLite cuma nerapin state terakhir.

Pas saya rakit ulang state transaksi pertama (cuma frame 0 sampai 4), hasilnya beda jauh: kalau
state akhir cuma punya id 1-4, state pertama punya delapan pesan, id 1-4 plus id 10-13 di thread
baru `kurir`. Jadi tersangkanya ngehapus thread `kurir`, tapi penghapusan itu sendiri kan jadi
transaksi baru, dan state sebelumnya tetep nyangkut di WAL.

(Detail iseng: `salt1`/`salt2` di header WAL isinya `0x53414c54`/`0x43494e44`, ASCII-nya "SALT" dan
"CIND". Jadi WAL-nya emang disusun tangan sama penulis soal, bukan hasil pemakaian app beneran.)

---

### ⚔️ Exploitation

Solver lengkapnya di [`Cinder-solved.py`](Cinder-solved.py), jalanin dari folder yang ada
`com.example.cinder/`-nya:

```bash
$ python3 Cinder-solved.py
```

Yang penting scriptnya nggak ngerusak bukti: `chat.db` asli dibaca sebagai bytes doang, tiap state
transaksi dirakit di memori, ditulis ke file sementara buat dibaca sqlite3, terus dihapus lagi.
Parameter kripto dibaca dari `secure_prefs.xml`, dan page size / jumlah frame / jumlah transaksi
diturunin dari header WAL (bukan dihardcode).

Alurnya: parse header WAL, kelompokin frame per transaksi (batas = frame dengan `dbsize > 0`),
rakit ulang state tiap transaksi, dekripsi pesan (AES-256-GCM, AAD `f"{thread}:{rowid}"`), terus
bandingin state lama vs baru buat nandain pesan yang dihapus.

![Solver jalan sampai flag keluar](img/03-flag.png)

<details>
<summary>Log lengkap</summary>

```text
[*] Membaca konfigurasi dari: com.example.cinder/shared_prefs/secure_prefs.xml
[+] Kunci enkripsi berhasil diturunkan via PBKDF2.
[*] Ukuran Halaman (Page Size) terdeteksi: 512 bytes
[*] Total Frame di WAL terdeteksi: 10 frames
[*] Total Transaksi ditemukan dalam WAL: 2

============================================================
 LAPORAN ANALISIS FORENSIK: REKONSTRUKSI WAL CINDER
============================================================

[+] State Database pada Transaksi ke-1 (8 pesan):
    - ID: 1 | Thread: family | Pengirim: mama | Pesan: jangan lupa beli galon ya nak
    - ID: 2 | Thread: family | Pengirim: me | Pesan: iya ntar sore mampir
    - ID: 3 | Thread: family | Pengirim: mama | Pesan: makasih :)
    - ID: 4 | Thread: cs-toko | Pengirim: toko_official | Pesan: Pesanan #A2213 sudah dikirim, resi JX9920.
    - ID: 10 | Thread: kurir | Pengirim: me | Pesan: arsip klien sudah gue compress + encrypt
    - ID: 11 | Thread: kurir | Pengirim: N | Pesan: mantap. drop kunci vault-nya di sini
    - ID: 12 | Thread: kurir | Pengirim: me | Pesan: vault manifest - internal, do not forward
packed the following into vault.7z (AES) before wipe:
  - 2024Q3_client_contracts/*.pdf (42 files)
  - payroll_export_nov.xlsx
  - infra/prod_db_dump.sql.gz
  - keys/deploy_id_ed25519 (rotate after handoff)
  - board_minutes_2024-10.docx
handoff: split archive uploaded to the usual dead-drop in 3 parts;
part hashes recorded in the courier thread. once N confirms receipt,
purge local copies and clear this thread (disappearing mode is on).
reminder: do NOT reuse the old passphrase scheme, N flagged it last time.
vault key: GEMASTIK19{n0t_burn3d_just_h1d1ng_1n_th3_w4l}

    - ID: 13 | Thread: kurir | Pengirim: N | Pesan: diterima. hapus chat ini sekarang

[+] State Database pada Transaksi ke-2 (4 pesan):
    - ID: 1 | Thread: family | Pengirim: mama | Pesan: jangan lupa beli galon ya nak
    - ID: 2 | Thread: family | Pengirim: me | Pesan: iya ntar sore mampir
    - ID: 3 | Thread: family | Pengirim: mama | Pesan: makasih :)
    - ID: 4 | Thread: cs-toko | Pengirim: toko_official | Pesan: Pesanan #A2213 sudah dikirim, resi JX9920.

------------------------------------------------------------
[!] TEMUAN UTAMA: PESAN YANG DIHAPUS PADA TRANSAKSI BERIKUTNYA
------------------------------------------------------------
    [DITEMUKAN DI WAL WALKBACK] ID: 10 | Thread: kurir | Pengirim: me | Pesan: arsip klien sudah gue compress + encrypt
    [DITEMUKAN DI WAL WALKBACK] ID: 11 | Thread: kurir | Pengirim: N | Pesan: mantap. drop kunci vault-nya di sini
    [DITEMUKAN DI WAL WALKBACK] ID: 12 | Thread: kurir | Pengirim: me | Pesan: vault manifest - internal, do not forward
packed the following into vault.7z (AES) before wipe:
  - 2024Q3_client_contracts/*.pdf (42 files)
  - payroll_export_nov.xlsx
  - infra/prod_db_dump.sql.gz
  - keys/deploy_id_ed25519 (rotate after handoff)
  - board_minutes_2024-10.docx
handoff: split archive uploaded to the usual dead-drop in 3 parts;
part hashes recorded in the courier thread. once N confirms receipt,
purge local copies and clear this thread (disappearing mode is on).
reminder: do NOT reuse the old passphrase scheme, N flagged it last time.
vault key: GEMASTIK19{n0t_burn3d_just_h1d1ng_1n_th3_w4l}

    [DITEMUKAN DI WAL WALKBACK] ID: 13 | Thread: kurir | Pengirim: N | Pesan: diterima. hapus chat ini sekarang
```
</details>

---

### 🚩 Flag

```
GEMASTIK19{n0t_burn3d_just_h1d1ng_1n_th3_w4l}
```

---

### 📒 Catatan

- Buka bukti pakai tool standar bisa ngerusak: SQLite nge-checkpoint tanpa nanya, dan WAL-nya
  ilang. Buat forensik, selalu salin dulu dan parse formatnya sendiri.
- WAL itu kayak tempat sampah yang nggak pernah dikosongin. Tiap commit ninggalin state sebelumnya,
  dan ngehapus baris justru nambah frame baru, bukan ngilangin yang lama.
- Kunci sering nangkring lengkap di aplikasinya sendiri. `shared_prefs` yang namanya "secure_prefs"
  itu ironi yang beneran sering kejadian di app Android.
- Cek format flag sebelum submit. Draft `GEMASTIK{` (tanpa `19`) itu umpan.
