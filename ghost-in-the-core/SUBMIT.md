# Panduan Submit - Ghost in the Core (Forensics 384)

**Flag:** `GEMASTIK19{gh0st_1n_th3_c0re_rc4_s4lt_fr0m_3nv1r0n}`

Form submit GEMASTIK minta tiga hal:

| Field form | Diisi apa |
|---|---|
| **AI SOURCE (LINK)** | https://share.gemini.google/v7qNRRJBIv7c |
| **SOLVER / SCRIPT** | upload file `ghost-solved.py` |
| **Flag** | `GEMASTIK19{gh0st_1n_th3_c0re_rc4_s4lt_fr0m_3nv1r0n}` |

Karena kita solve pakai script, yang wajib cuma dua: link chat AI + file `ghost-solved.py`.
Screenshot sifatnya pelengkap.

---

## 1. Foto soal

Screenshot modal soal Ghost in the Core (judul "Ghost in the Core", poin 384, deskripsi
aether-sensor-07, Author aodreamer, tombol download). Simpan sebagai `img/01-soal.png`.

---

## 2. Cara isi form submit

1. Buka modal soal Ghost in the Core, tempel link chat ke **AI SOURCE (LINK)**.
2. Klik **Choose Files** di **SOLVER / SCRIPT**, pilih `ghost-solved.py`.
3. Ketik flag: `GEMASTIK19{gh0st_1n_th3_c0re_rc4_s4lt_fr0m_3nv1r0n}`
4. Klik **Submit**.

---

## 3. Screenshot pelengkap

Kalau mau bukti proses, ambil dua SS ini:

| # | Simpan sebagai | Isinya |
|---|---|---|
| 1 | `img/02-recon.png` | parse pcap (dapat 51 byte) + `readelf -n victim.core` (mapping `/tmp/build.../sensor`) + `strings sensor` (env samaran) |
| 2 | `img/03-flag.png` | `python3 ghost-solved.py` sampai baris flag muncul |

Yang paling penting SS flag: perintah dan baris `GEMASTIK19{...}` harus kelihatan barengan.

---

## 4. Link chat AI

**Link:** https://share.gemini.google/v7qNRRJBIv7c

Chat AI kamu lengkap dari recon awal (arti core dump + pcap, cara carve binary fileless, cara
kenali cipher non-standar dari disassembly, tempat sembunyi kunci di proses Linux, arti "wiped its
working buffers"), sampai bedah rantai kunci RC4 berlapis (fixed key + salt env buat config, terus
secret `S=` buat payload) dan penyusunan solver stdlib.

Spek link:

- Satu chat khusus untuk soal ini.
- Set link ke publik (Gemini: Share -> Create public link).
- Tes dulu di incognito (belum login). Kalau kebuka, aman ditempel ke form.
- Tempel apa adanya, jangan dipendekin.
