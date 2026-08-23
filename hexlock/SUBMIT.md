# Panduan Submit - hexlock (Reverse 500)

**Flag:** `GEMASTIK19{6_sh4rd5_r34ss3mbl3_th3_g0ph3r5_s3cr3t}`

Form submit GEMASTIK minta tiga hal:

| Field form | Diisi apa |
|---|---|
| **AI SOURCE (LINK)** | https://share.gemini.google/KGVvD7Uw2ofF |
| **SOLVER / SCRIPT** | upload file `hexlock-solved.py` |
| **Flag** | `GEMASTIK19{6_sh4rd5_r34ss3mbl3_th3_g0ph3r5_s3cr3t}` |

Karena kita solve pakai script, yang wajib cuma dua: link chat AI + file `hexlock-solved.py`.
Screenshot sifatnya pelengkap.

---

## 1. Foto soal

Screenshot modal soal hexlock (judul "hexlock", poin 500, deskripsi "Line to codes?...",
Author wondping0, tombol download). Simpan sebagai `img/01-soal.png`.

---

## 2. Cara isi form submit

1. Buka modal soal hexlock, tempel link chat ke **AI SOURCE (LINK)**.
2. Klik **Choose Files** di **SOLVER / SCRIPT**, pilih `hexlock-solved.py`.
3. Ketik flag: `GEMASTIK19{6_sh4rd5_r34ss3mbl3_th3_g0ph3r5_s3cr3t}`
4. Klik **Submit**.

---

## 3. Screenshot pelengkap

Kalau mau bukti proses, ambil dua SS ini (semua di terminal, satu layar per momen):

| # | Simpan sebagai | Isinya |
|---|---|---|
| 1 | `img/02-recon.png` | `file hexlock`, cek runtime Go, `nm` no symbols, gopclntab |
| 2 | `img/03-flag.png` | `python3 hexlock-solved.py` sampai baris `Correct!` |

Yang paling penting SS flag: `python3 hexlock-solved.py` dan `Correct!` harus kelihatan barengan.

---

## 4. Link chat AI

**Link:** https://share.gemini.google/KGVvD7Uw2ofF

Chat AI kamu lengkap dari recon (identifikasi Go + garble), parsing `.gopclntab` manual, nemu
`main` lewat XREF string, sampai debugging berlapis: MAC check failed, ketemu anti-debug + self
integrity, sadar mixing key per-byte, terus brute-force 4096 + tag GCM. Bagian yang error (typo
`len.bit_length`, regex gdb kena alamat memori, `errors='ignore'`) sengaja dibiarkan, itu justru
bukti kamu beneran ngerjain.

Spek link:

- Satu chat khusus untuk soal ini, jangan dicampur soal lain.
- Set link ke publik (Gemini: Share -> Create public link).
- Tes dulu di incognito (belum login). Kalau kebuka, aman ditempel ke form. Ini penyebab paling
  umum submission ditolak: link masih private.
- Tempel apa adanya, jangan dipendekin.
