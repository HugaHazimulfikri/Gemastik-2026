# `Ecliprime` — crypto

> 🏷️ **Challenge metadata**

|                  |                    |                |                        |
| ---------------- | ------------------ | -------------- | ---------------------- |
| 🏆 **Event**     | `Gemastik 2026`    | 📅 **Date**    | `2026-08-23`           |
| 🏷️ **Category** | `crypto`           | 💯 **Points**  | `100`                  |
| 👤 **Author**    | `ac3`              | 🧑‍💻 **Team** | `DOSCOM`              |

---

### 📝 Deskripsi Soal

> **Description dari panitia:**
>
> Saat gerhana menutupi sebagian besar bilangan prima, jejak kecilnya masih tertinggal dalam bayangan. Sebuah pesan telah diamankan menggunakan RSA dan enkripsi berlapis, tetapi salah satu faktor penyusunnya tidak sepenuhnya tersembunyi.

**📎 Attachment:**

| File | Tipe | Ukuran |
|---|---|---|
| `challenge.py` | python | 1.2 KB |

---

### 🔍 Analisis Awal (Recon)

Berdasarkan analisis file `challenge.py`, kita diberikan beberapa parameter penting RSA beserta
komponen enkripsi lapis keduanya:

* **Modulus ($N$):** Berukuran 1023 bit, yang berarti faktor prima $p$ dan $q$ masing-masing
  berukuran sekitar 512 bit.
* **$p_{high}$:** Bilangan 512 bit di mana 200 bit bagian bawahnya bernilai nol sebagai
  *placeholder* ($p_{high} \pmod{2^{200}} == 0$).
* **Variabel Pengecoh (`oaep_ciphertext`):** Disediakan di dalam file, namun setelah ditelusuri
  pada fungsi penurunan kunci, variabel ini sama sekali tidak pernah digunakan (sebagai *decoy* /
  umpan).
* **Jalur Kunci (`derive_key`):** Kunci AES diturunkan langsung dari faktor prima $p$ melalui
  HKDF-SHA256 menggunakan parameter $p_{small}$ dan $d_p$.

---

### 🧠 Eksploitasi: Metode Coppersmith

Karena sebagian besar bit dari $p$ sudah diketahui ($p_{high}$) dan hanya menyisakan 200 bit yang
tidak diketahui ($M = 200$), kita dapat memanfaatkan **Coppersmith's Method** untuk mencari akar
kecil dari polinomial modulo $N$.

Batas teoretis Coppersmith untuk pemulihan sebagian bit faktor adalah setengah dari panjang bit
faktor itu sendiri ($\le 256$ bit untuk $p$ 512 bit). Karena nilai $M = 200$ berada di bawah batas
tersebut, metode ini aman dan dapat digunakan.

Langkah-langkah pembentukan polinomial dan pencarian akar kecil menggunakan SageMath:

1. Definisikan ring polinomial di atas $\mathbb{Z}_N$.
2. Buat polinomial monik: $f(x) = p_{high} + x$.
3. Jalankan fungsi `small_roots` dengan batas pencarian akar selebar $2^{200}$ ($X = 2^{200}$).

---

### ⚔️ Implementasi Solver Python & SageMath

Berikut adalah kode *script solver* lengkap ([`solve.sage`](solve.sage)) untuk mengekstrak nilai
$p$, memverifikasi faktor $N$, menurunkan kunci, serta mendekripsi flag AES-256-GCM:

```python
import importlib
from Crypto.Cipher import AES

# 1. Mengimpor modul challenge.py secara dinamis
challenge = importlib.import_module("challenge")

N = challenge.N
e = challenge.e
M = challenge.M
p_high = challenge.p_high
flag_enc = challenge.flag_enc

# 2. Validasi struktur bit bawah p_high sesuai permintaan
assert p_high % (2**M) == 0, "Asumsi struktur p_high tidak sesuai dengan M!"
print(f"[+] Validasi bit bawah p_high sukses (mod 2^{M} == 0).")

# 3. Rekonstruksi p menggunakan Coppersmith's Method
P.<x> = PolynomialRing(Zmod(N))
f = (p_high + x).monic()

roots = f.small_roots(X=2^M, beta=0.4, epsilon=0.02)

if roots:
    x_val = int(roots[0])
    p = p_high + x_val
    print(f"[+] Berhasil menemukan x: {x_val}")
    print(f"[+] Nilai p ditemukan: {p}")

    # Validasi faktor N
    if N % p == 0:
        q = N // p
        print(f"[+] Validasi sukses! p adalah faktor dari N. (q = {q})")

        # 4. Memanggil fungsi derive_key asli dari modul challenge
        key = challenge.derive_key(int(p))

        # 5. Dekripsi AES-256-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(flag_enc["nonce"]))
        ciphertext_bytes = bytes.fromhex(flag_enc["ciphertext"])
        tag_bytes = bytes.fromhex(flag_enc["tag"])

        try:
            flag = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
            print(f"\n[!] FLAG KETEMU: {flag.decode('utf-8')}")
        except Exception as err:
            print(f"[-] Gagal dekripsi: {err}")
    else:
        print("[-] Nilai p bukan faktor dari N.")
else:
    print("[-] Akar kecil tidak ditemukan.")
```

**Bukti Hasil Eksekusi.** Setelah skrip di atas dijalankan menggunakan lingkungan SageMath
(`sage solve.sage`), proses dekripsi berjalan sukses dan mengeluarkan hasil berikut:
<img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/d7f24ee5-a620-469e-a816-8aeea20f345c" />

---

### 🚩 Flag

```
GEMASTIK19{c0pp3rsm1th_g4t3d_kdf_d3c0y_0aep_n34r_th3_b0und}
```

### 🤖 AI Chat

```
https://share.gemini.google/vbAepMkkYjs1
```
