# Panduan Submit - mantra (PWN / Kernel 481)

**Flag:** `GEMASTIK19{n0t_4ll_p01nt3rs_p01nt_s0m3wh3r3_s0m3_p01nt_t0_z3r0}`

Form submit GEMASTIK minta tiga hal:

| Field form | Diisi apa |
|---|---|
| **AI SOURCE (LINK)** | https://share.gemini.google/KxYrdoKVUwA0 |
| **SOLVER / SCRIPT** | upload `solve_tiny.c` + `exploit.py` |
| **Flag** | `GEMASTIK19{n0t_4ll_p01nt3rs_p01nt_s0m3wh3r3_s0m3_p01nt_t0_z3r0}` |

Karena kita solve pakai script, yang wajib cuma dua: link chat AI + file solver.
`exploit.py` yang otomatis kompilasi `solve_tiny.c` lalu kirim ke remote, jadi upload dua-duanya.
Screenshot sifatnya pelengkap.

---

## 1. Foto soal

Screenshot modal soal mantra (judul "mantra", poin 481, deskripsi "pemanasan dulu biar panas ya
mas" + `print(10+6)`, `nc 15.232.64.175 13338`, Author hanzo, tombol download handout). Simpan
sebagai `img/01-soal.png`.

---

## 2. Cara isi form submit

1. Buka modal soal mantra, tempel link chat ke **AI SOURCE (LINK)**.
2. Klik **Choose Files** di **SOLVER / SCRIPT**, pilih `solve_tiny.c` dan `exploit.py`.
3. Ketik flag: `GEMASTIK19{n0t_4ll_p01nt3rs_p01nt_s0m3wh3r3_s0m3_p01nt_t0_z3r0}`
4. Klik **Submit**.

---

## 3. Screenshot pelengkap

Kalau mau bukti proses, ambil dua SS ini:

| # | Simpan sebagai | Isinya |
|---|---|---|
| 1 | `img/02-recon.png` | `cat run.sh` + `cat rootfs/init` (nokaslr, SMAP off, `mmap_min_addr=0`) atau objdump ioctl (bandingin `test rbx,rbx` yang ada vs hilang) |
| 2 | `img/03-flag.png` | `python3 exploit.py` sampai baris `=== FLAG OUTPUT ===` + flag |

Yang paling penting SS flag: perintah dan baris `GEMASTIK19{...}` harus kelihatan barengan.

---

## 4. Link chat AI

**Link:** https://share.gemini.google/KxYrdoKVUwA0

Chat AI kamu lengkap dari analisis mitigasi (SMEP/nokaslr/nopti/SMAP + `mmap_min_addr=0`), arti
`misc_register` dan skenario LPE, decompile `mantra_ioctl` jadi C pseudocode, penemuan bug NULL-deref
di READ/XOR (dua handler yang lupa cek `private_data`), sampai penyusunan exploit `modprobe_path`
overwrite dan dua putaran perbaikan bug solver (constraint register syscall + langkah trigger
modprobe yang harus di dalam binary C, bukan di Python). Bagian yang error/direvisi sengaja
dibiarkan, itu justru bukti proses.

Spek link:

- Satu chat khusus untuk soal ini.
- Set link ke publik (Gemini: Share -> Create public link).
- Tes dulu di incognito (belum login). Kalau kebuka, aman ditempel ke form.
- Tempel apa adanya, jangan dipendekin.
