# Panduan Submit - Tombstone (Forensics 500)

**Flag:** `GEMASTIK19{th3_cl0ck_l13d_but_th3_1n0d3_d1dnt}`

Form submit GEMASTIK minta tiga hal:

| Field form | Diisi apa |
|---|---|
| **AI SOURCE (LINK)** | https://share.gemini.google/CUKyDMIPgQwT |
| **SOLVER / SCRIPT** | upload file `Tombstone-solved.py` |
| **Flag** | `GEMASTIK19{th3_cl0ck_l13d_but_th3_1n0d3_d1dnt}` |

Karena kita solve pakai script, yang wajib cuma dua: link chat AI + file `Tombstone-solved.py`.
Screenshot sifatnya pelengkap.

---

## 1. Foto soal

Screenshot modal soal Tombstone (judul "Tombstone", poin 500, deskripsi, Author aodreamer, tombol
download). Simpan sebagai `img/01-soal.png`.

---

## 2. Cara isi form submit

1. Buka modal soal Tombstone, tempel link chat ke **AI SOURCE (LINK)**.
2. Klik **Choose Files** di **SOLVER / SCRIPT**, pilih `Tombstone-solved.py`.
3. Ketik flag: `GEMASTIK19{th3_cl0ck_l13d_but_th3_1n0d3_d1dnt}`
4. Klik **Submit**.

---

## 3. Screenshot pelengkap

Kalau mau bukti proses, ambil dua SS ini:

| # | Simpan sebagai | Isinya |
|---|---|---|
| 1 | `img/02-recon.png` | `fls -r -p fin-ws-04.img` atau `debugfs -R "stat ..."` (timestamp forged vs crtime asli) |
| 2 | `img/03-flag.png` | `python3 Tombstone-solved.py` sampai baris `FLAG FOUND` |

Yang paling penting SS flag: perintah dan baris `GEMASTIK19{...}` harus kelihatan barengan.

---

## 4. Link chat AI

**Link:** https://share.gemini.google/CUKyDMIPgQwT

Chat AI kamu lengkap dari recon (arti "Tombstone", file mencurigakan, wtmp/btmp/audit yang selamat,
risiko mount ext4), penemuan `.python_history` + cron `geoclue-refresh`, sampai bedah crtime vs
ctime dan dua putaran perbaikan solver (dari `tar.extractall` ke ekstraksi in-memory + pencarian
flag). Bagian yang error/direvisi sengaja dibiarkan, itu justru bukti proses.

Spek link:

- Satu chat khusus untuk soal ini.
- Set link ke publik (Gemini: Share -> Create public link).
- Tes dulu di incognito (belum login). Kalau kebuka, aman ditempel ke form.
- Tempel apa adanya, jangan dipendekin.
