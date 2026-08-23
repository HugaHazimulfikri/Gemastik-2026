# Panduan Submit - Nonce-nse (Crypto 500)

**Flag:** `GEMASTIK19{hnp_sh0rt_b14s3d_n0nc3_l4tt1c3_g4t3d_kdf}`

Form submit GEMASTIK minta tiga hal:

| Field form | Diisi apa |
|---|---|
| **AI SOURCE (LINK)** | https://share.gemini.google/EnHFKP9tDmzz |
| **SOLVER / SCRIPT** | upload file `solve-dsoal-nonce.sg` |
| **Flag** | `GEMASTIK19{hnp_sh0rt_b14s3d_n0nc3_l4tt1c3_g4t3d_kdf}` |

Karena kita solve pakai script, yang **wajib** cuma dua: link chat AI + file `solve-dsoal-nonce.sg`.
Screenshot sifatnya pelengkap (bagian 3), bukan keharusan.

---

## 1. Foto soal

Screenshot yang perlu diambil dari platform (buat arsip pribadi / kalau panitia minta bukti):

- **Modal soal Nonce-nse** yang menampilkan judul "Nonce-nse", poin 500, deskripsi
  ("Sebuah sistem meninggalkan jejak dari banyak tanda tangan digital..."), Author: ac3,
  dan tombol download `challenge.py`.

Cara ambil: buka soal di scoreboard, screenshot seluruh modal-nya (pastikan judul + poin + Author
kelihatan). Simpan sebagai `nonce-nse/soal.png`.

---

## 2. Cara isi form submit

1. Buka modal soal Nonce-nse, klik area **AI SOURCE (LINK)**, tempel link chat (bagian 4).
2. Klik **Choose Files** di **SOLVER / SCRIPT**, pilih `solve-dsoal-nonce.sg`.
3. Ketik flag di kotak **Flag**: `GEMASTIK19{hnp_sh0rt_b14s3d_n0nc3_l4tt1c3_g4t3d_kdf}`
4. Klik **Submit**.

---

## 3. Tahapan yang perlu di-screenshot (pelengkap)

Kalau mau bukti proses yang kuat (misal diminta panitia atau buat jaga-jaga wawancara), ambil SS
tiga momen ini. Semua di terminal, satu frame per momen:

| # | Momen | Isi yang harus kelihatan |
|---|---|---|
| 1 | **Recon** | perintah + output yang membuktikan kurva secp256k1 dan `nonce_bits_hint = 160`. Contoh: `grep -n "nonce_bits_hint\|^n =" challenge.py` |
| 2 | **Cek bukan nonce reuse** | `grep '"r":' challenge.py \| sort \| uniq -d` yang keluarannya kosong (membuktikan tidak ada `r` kembar) |
| 3 | **Solver jalan + flag** | `sage solve-dsoal-nonce.sg` dari awal sampai baris `FLAG BERHASIL DIDAPATKAN: GEMASTIK19{...}` dalam satu layar |

Yang paling penting SS #3: perintah `sage solve-dsoal-nonce.sg` dan flag-nya harus dalam satu frame, jangan
di-crop cuma flag-nya.

---

## 4. Link chat AI cara buat & spek

### Isi chat-nya

**Link:** https://share.gemini.google/EnHFKP9tDmzz

Chat AI kamu sudah lengkap: mulai dari prompt recon, lalu debugging berlapis (OverflowError →
`ZZ()` → `scalar_mult` → `EllipticCurve` → hex decode) sampai flag keluar. **Jangan hapus bagian
yang error** justru transkrip yang menunjukkan proses debugging itu bukti kuat kamu benar-benar
mengerjakan, bukan nyalin jawaban jadi.

### Spek link yang benar

- **Satu chat khusus untuk soal ini.** Jangan campur Nonce-nse dengan soal lain di satu percakapan.
- **Set link ke publik.** ChatGPT: tombol *Share* → *Create link*. Gemini: *Share* → *Create public
  link*. Claude: *Share*.
- **Tes dulu di incognito.** Buka link hasil share di jendela penyamaran (belum login) kalau
  isinya kebuka, berarti link-nya publik dan aman ditempel ke form. Ini penyebab paling umum
  submission ditolak: link masih private.
- **Tempel apa adanya** ke field AI SOURCE, jangan dipendekin pakai bit.ly dsb.

### Prompt pembuka (bahasa ngobrol)

Kalau mau bikin chat baru yang rapi dari awal, lampirkan `challenge.py` lalu kirim ini:

---

Halo, aku lagi ngerjain soal CTF kripto namanya "Nonce-nse". Analisisnya udah aku kerjain sendiri,
sekarang tinggal butuh bantuan bikin solver-nya. File soalnya `challenge.py` aku lampirin ya.

Jadi isi filenya itu ada konstanta `n`, `G`, `Q`, satu variabel `nonce_bits_hint = 160`, list 40
signature yang masing-masing isinya `(i, msg, h, r, s)`, dict `flag_enc` (AES-256-GCM: nonce,
ciphertext, tag), plus fungsi `hkdf_sha256()`, `derive_key(d)`, sama `seal_flag(d, flag)`.

Yang pertama aku cek nilai `n`-nya, ternyata persis sama dengan
`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`, jadi ini kurva secp256k1
(`p = 2^256 - 2^32 - 977`, `y^2 = x^3 + 7`). `Q` itu public key, `G` generator standar.

Awalnya aku curiga nonce reuse, tapi setelah aku cek semua nilai `r` dari 40 signature ternyata
nggak ada yang kembar, jadi bukan itu. Yang bikin curiga malah `nonce_bits_hint = 160`: kalau `n`
panjangnya 256 bit tapi nonce `k` cuma 160 bit, berarti ada bias 96 bit. Jadi `k` selalu jatuh di
`[0, 2^160)`, nggak nyebar merata di `[1, n)`.

Menurutku ini Hidden Number Problem. Dari persamaan ECDSA `s = k^-1 (h + r*d) mod n`, kalau disusun
ulang biar linier terhadap `d` jadinya `k_i = s_i^-1*h_i + s_i^-1*r_i*d mod n`, alias
`k_i = a_i + t_i*d mod n`. `a_i` sama `t_i` bisa dihitung dari data signature, `d` nggak diketahui,
dan `k_i` juga nggak diketahui tapi kecil (di bawah `B = 2^160`). Itu kan persis bentuk HNP, jadi
mestinya bisa diselesaikan pakai reduksi lattice (LLL).

Rencana lattice-ku: bikin basis `(m+2) x (m+2)` buat `m = 40` signature. Baris 0..m-1 isinya `n` di
diagonal, baris m isinya `[t_0..t_{m-1}, B/n, 0]`, baris m+1 isinya `[a_0..a_{m-1}, 0, B]`.
Kombinasi yang bener bakal ngasih vektor pendek `(k_0..k_{m-1}, d*B/n, B)` yang bisa ditemukan LLL.
Aku juga mau pakai recentering `a_i -> a_i - B/2` biar `k_i` geser ke `[-B/2, B/2)` dan norm
targetnya turun setengah. Secara teori cuma butuh sekitar `256/96 ~ 3` signature, dikasih 40 berarti
longgar banget, LLL biasa mestinya cukup tanpa BKZ.

Buat ngambil `d`-nya, dari baris hasil LLL yang entri terakhirnya `±B`, `d = ± row[m] * n / B mod n`.
Karena LLL ngeluarin banyak vektor pendek dan tandanya bisa kebalik, ini harus dicek satu-satu ke
`d*G == Q`. Habis `d` ketemu tinggal panggil `derive_key(d)` yang udah ada di file soal (HKDF-SHA256)
buat dapetin kunci AES-256, terus decrypt `flag_enc`.

Tolong implementasiin analisis di atas jadi solver yang jalan ya.

Environmentku Arch Linux, Python 3.13, ada SageMath, fpylll, pycryptodome, sympy. Boleh pakai Sage
(`Matrix(QQ).LLL()` sama `EllipticCurve` bawaannya).

Beberapa yang aku harepin dari scriptnya: satu file `solve-dsoal-nonce.sg` yang jalan pakai `sage solve-dsoal-nonce.sg`
dari folder yang sama sama `challenge.py`. Datanya dibaca langsung dari `challenge.py` pakai
importlib, jangan diketik ulang soalnya 40 signature itu angkanya panjang rawan typo, dan jangan
hardcode `n`/`G`/`Q`/`nonce_bits_hint`. Bangun lattice HNP sesuai rencana termasuk recentering.
Wajib loop ke semua baris hasil LLL dan coba dua-duanya (positif sama negatif), terus verifikasi
tiap kandidat ke `d*G == Q` kalau nggak ada yang lolos, scriptnya bilang gagal aja jangan
nge-print `d` ngawur. Habis `d` valid, panggil `derive_key()` punya soal, terus pakai
`decrypt_and_verify()` (bukan `decrypt()` biasa) biar tag GCM sekalian jadi bukti kuncinya bener.
Kasih print progres tiap tahap, jangan ada TODO atau placeholder.

Oh iya, environmentku Sage di atas Python 3.14, jadi tolong hati-hati: perkalian titik kurva pakai
`int` Python besar bisa kena OverflowError, dan `G`/`Q` di file itu tuple biasa bukan objek titik.
Jadi tolong bangun kurvanya eksplisit (`E = EllipticCurve(GF(p), [0,7])`), angkat `G`/`Q` jadi titik
(`E(G[0], G[1])`), pakai `d_cand * G_pt == Q_pt` buat verifikasi, dan cek `flag_enc` itu string hex
yang perlu `bytes.fromhex()` dulu sebelum masuk `AES.new()`.

---

Catatan: paragraf terakhir itu sengaja ditambahkan supaya AI langsung menghindari tiga bug yang
kemarin muncul (OverflowError perkalian titik, `G`/`Q` masih tuple, `flag_enc` string hex). Kalau
kamu pakai chat lama yang sudah memuat debugging tiga bug itu, biarkan saja apa adanya transkrip
debugging justru menambah nilai.
