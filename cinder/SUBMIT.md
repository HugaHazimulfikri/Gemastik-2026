# Panduan Submit - Cinder (Forensics 100)

**Flag:** `GEMASTIK19{n0t_burn3d_just_h1d1ng_1n_th3_w4l}`

Form submit GEMASTIK minta tiga hal:

| Field form | Diisi apa |
|---|---|
| **AI SOURCE (LINK)** | https://share.gemini.google/qwuktsUlIDg9 |
| **SOLVER / SCRIPT** | upload file `Cinder-solved.py` |
| **Flag** | `GEMASTIK19{n0t_burn3d_just_h1d1ng_1n_th3_w4l}` |

Karena kita solve pakai script, yang wajib cuma dua: link chat AI + file `Cinder-solved.py`.
Screenshot sifatnya pelengkap.

---

## 1. Foto soal

Screenshot modal soal Cinder (judul "Cinder", poin 100, deskripsi, Author aodreamer, tombol
download). Simpan sebagai `img/01-soal.png`.

---

## 2. Cara isi form submit

1. Buka modal soal Cinder, tempel link chat ke **AI SOURCE (LINK)**.
2. Klik **Choose Files** di **SOLVER / SCRIPT**, pilih `Cinder-solved.py`.
3. Ketik flag: `GEMASTIK19{n0t_burn3d_just_h1d1ng_1n_th3_w4l}`
4. Klik **Submit**.

---

## 3. Screenshot pelengkap

Kalau mau bukti proses, ambil dua SS ini:

| # | Simpan sebagai | Isinya |
|---|---|---|
| 1 | `img/02-recon.png` | isi folder sandbox + `secure_prefs.xml` (struktur WAL kelihatan) |
| 2 | `img/03-flag.png` | `python3 Cinder-solved.py` sampai baris flag muncul |

Yang paling penting SS flag: perintah dan baris `GEMASTIK19{...}` harus kelihatan barengan.

---

## 4. Link chat AI

**Link:** https://share.gemini.google/qwuktsUlIDg9

Chat AI kamu lengkap dari recon (arti WAL/-shm, peringatan "work on a copy", analisis
secure_prefs), sampai bedah struktur biner WAL dan rekonstruksi transaksi pertama yang memuat
thread `kurir` yang dihapus.

Spek link:

- Satu chat khusus untuk soal ini.
- Set link ke publik (Gemini: Share -> Create public link).
- Tes dulu di incognito (belum login). Kalau kebuka, aman ditempel ke form.
- Tempel apa adanya, jangan dipendekin.
