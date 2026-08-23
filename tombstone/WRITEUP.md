# 🏁 CTF Writeup - `GEMASTIK XIX 2026 - Keamanan Siber (Penyisihan)`

Writeup challenge **`Tombstone`**.

---

# `Tombstone` - forensics

|                  |                          |                |                                     |
| ---------------- | ------------------------ | -------------- | ----------------------------------- |
| 🏆 **Event**     | `GEMASTIK XIX 2026`      | 📅 **Date**    | `2026-08-24`                        |
| 🏷️ **Category** | `forensics`              | 💯 **Points**  | `500`                               |
| ⭐ **Difficulty** | ★★★★☆                    | 👤 **Author**  | `aodreamer`                         |
| 🧑‍💻 **Team**    | `<isi nama tim>`         | 🛠️ **Tools**  | `debugfs, python (pycryptodome)`    |
| 🤖 **AI Source** | https://share.gemini.google/CUKyDMIPgQwT | 🧩 **Solver** | [`Tombstone-solved.py`](Tombstone-solved.py) |
| 🔖 **Tags**      | `#ext4` `#crtime` `#xattr` `#anti-forensics` `#aes-gcm` | | |

---

### 📝 Deskripsi Soal

> DLP flagged outbound traffic from a finance workstation, well after hours. We pulled the disk
> image before anyone could touch it again.
>
> Rekonstruksi apa yang terjadi malam itu: siapa yang masuk, dari mana, kapan, dan gimana datanya
> keluar. Treat the image as evidence and work on a copy.
>
> Author: aodreamer

Attachment: `fin-ws-04.img` (disk image ext4, 48 MB).

![Modal soal Tombstone](img/01-soal.png)

---

### 🔍 Reconnaissance

`SOC_NOTE.md` bilang jejak gampangnya udah dibersihin: `auth.log` dipotong, journal systemd
di-vacuum, `.bash_history` ilang. Aku baca isi image pakai The Sleuth Kit (tanpa mount, biar
journal replay nggak ngerusak bukti):

```bash
$ fls -r -p fin-ws-04.img
r/r 40: home/dwi/.bash_history
r/r 41: home/dwi/.python_history
r/r 39: var/tmp/.ICE-unix/1000/.cache-dwi.dat
r/r 35: var/log/auth.log
r/r 37: var/log/wtmp
r/r 38: var/log/btmp
r/r 36: var/log/audit/audit.log
r/r 31: etc/cron.d/geoclue-refresh
r/r 34: usr/local/sbin/systemd-timesyncd-helper
...
```

![Recon Tombstone](img/02-recon.png)

Yang aku catat:

- `usr/local/sbin/systemd-timesyncd-helper` itu **masquerading**, namanya niru daemon systemd yang
  sah tapi ditaruh di `/usr/local/sbin`. Ini tool penyerangnya.
- `.cache-dwi.dat` di dalam `.ICE-unix` (harusnya buat X11 socket) itu payload staging.
- `.bash_history` nol byte, tapi `.python_history` masih utuh, dan isinya justru resep serangannya.
- `wtmp`, `btmp`, `audit.log` selamat karena format biner, penyerang sering lupa. Dari `btmp`:
  dua login gagal dari `10.13.37.7` (jam 20:39 sebagai `dwi`, 20:40 sebagai `root`), lalu `wtmp`:
  login berhasil dari IP yang sama jam 20:41.

---

### 🧠 Analisis

**Resep dari .python_history.** Penyerang hapus `.bash_history` tapi lupa `.python_history`:

```python
os.setxattr('/usr/local/sbin/systemd-timesyncd-helper', 'user.upl_b', part_b)
# vault key = PBKDF2(cron UPLOAD_ID + that xattr, salt = tool crtime as epoch), 200000
# packed /home/dwi/finance -> /var/tmp/.ICE-unix/1000/.cache-dwi.dat (AES-GCM, nonce||ct||tag)
```

Jadi kuncinya dipecah tiga, disebar di tempat beda:

1. `UPLOAD_ID` di `/etc/cron.d/geoclue-refresh` (nyamar jadi config geoclue): `3f9a1c7e5b2d8046a1c0`
2. `part_b` di **extended attribute** `user.upl_b` milik tool itu
3. salt = **crtime** inode tool

Dua yang terakhir nggak bisa diambil pakai `tsk_recover`/`cat`, karena itu metadata inode. Harus
lewat `debugfs -R "stat"`:

```
ctime: 0x63c34200 -- Sun Jan 15 07:00:00 2023
atime: 0x63c34200 -- Sun Jan 15 07:00:00 2023
mtime: 0x63c34200 -- Sun Jan 15 07:00:00 2023
crtime: 0x6733bdd4 -- Wed Nov 13 03:43:00 2024
Extended attributes:
  user.upl_b (20) = "8f2b6d1a0c7e9a4b3f51"
```

**Ini inti soalnya.** Tiga timestamp pertama seragam persis di Januari 2023, itu jelas hasil
`touch` biar tool-nya kelihatan bawaan sistem. Tapi **crtime nggak ikut dipalsuin** (12 November
2024 jam 20:43), pas di antara login jam 20:41 dan upload jam 20:45. Ironinya, penyerang milih
crtime jadi salt justru karena susah dipalsuin, tapi jadinya dia nggak bisa palsuin crtime buat
nutupin jejaknya sendiri. Dia ngunci dirinya ke timestamp yang jujur. Judul "Tombstone" pas banget.

**Umpan.** `BK_KEY=b17c0ffee5a1710d` di `/etc/cron.d/backup` + `state.enc` di `/opt/backup/`
kelihatan berpasangan, tapi `.python_history` jelas nyebut yang dipakai `UPLOAD_ID`, bukan `BK_KEY`.
Umpan.

---

### ⚔️ Exploitation

Solver lengkapnya di [`Tombstone-solved.py`](Tombstone-solved.py), jalanin dari folder yang ada
`fin-ws-04.img`-nya:

```bash
$ python3 Tombstone-solved.py
```

Yang penting: image-nya **nggak di-mount sama sekali**, semua pembacaan lewat `debugfs` subprocess
(termasuk `debugfs -R "cat <path>"`), jadi bukti nggak tersentuh. `UPLOAD_ID` di-regex dari cron,
`part_b` + `crtime` diparse dari output `debugfs stat`, nomor inode dicari dari field `Inode:` (bukan
dihardcode). Ekstraksi arsip dilakukan di memori (`getmembers`/`extractfile`), nggak nulis ke disk,
biar aman dari path traversal.

```
key = PBKDF2-HMAC-SHA256(UPLOAD_ID + part_b, str(crtime), 200000)
plain = AES-256-GCM.decrypt(.cache-dwi.dat, nonce||ct||tag)
gunzip -> tar -> drop_manifest.txt (ada flagnya)
```

![Solver jalan sampai flag keluar](img/03-flag.png)

<details>
<summary>Log lengkap</summary>

```text
[*] Step 1: Extracting UPLOAD_ID from cron configuration (/etc/cron.d/geoclue-refresh)...
[+] Successfully extracted UPLOAD_ID: 3f9a1c7e5b2d8046a1c0
[*] Step 2: Inspecting tool metadata (inode, timestamps, xattr) via debugfs stat...
[+] Target file Inode resolved dynamically: 34

----------------------------------------
           TIMESTAMP ANALYSIS
----------------------------------------
[*] mtime  : 1673740800 (Hex: 0x63c34200) -> [FORGED / TOUCHED]
[*] crtime : 1731444180 (Hex: 6733bdd4) -> [REAL / UNALTERED BIRTH TIME]
----------------------------------------

[+] Successfully extracted part_b from xattr: 8f2b6d1a0c7e9a4b3f51
[*] Step 3: Deriving Vault Key using PBKDF2-HMAC-SHA256 (200,000 iterations)...
[+] Derived Key (Hex): fa456c136b1856448dacf53cb6046c0b5e477ff9432974752c351a1fb38ddb2f
[*] Step 4: Extracting encrypted vault payload (/var/tmp/.ICE-unix/1000/.cache-dwi.dat)...
[+] Successfully extracted encrypted payload (346 bytes)
[*] Step 5: Decrypting and verifying payload with AES-GCM (Nonce: 12 bytes, Tag: 16 bytes)...
[+] AES-GCM Decryption successful! Cryptographic tag verified.
[*] Step 6: Inspecting archive contents safely in memory (no disk writes)...

--- File: q3_actuals.xlsx (Size: 36 bytes) ---
PK(placeholder spreadsheet bytes)

--- File: vendor_list.csv (Size: 36 bytes) ---
vendor,acct
ACME,88120
Globex,88231

--- File: drop_manifest.txt (Size: 117 bytes) ---
exfil manifest fin-ws-04
files staged and uploaded.
vault unlocked -> GEMASTIK19{th3_cl0ck_l13d_but_th3_1n0d3_d1dnt}

----------------------------------------
           FLAG SEARCH RESULTS
----------------------------------------
[+] FLAG FOUND: GEMASTIK19{th3_cl0ck_l13d_but_th3_1n0d3_d1dnt}
    File Path  : drop_manifest.txt
    Line Number: 3
----------------------------------------
```
</details>

---

### 🚩 Flag

```
GEMASTIK19{th3_cl0ck_l13d_but_th3_1n0d3_d1dnt}
```

---

### 📒 Catatan

- Kunci bisa nangkring di metadata (xattr, crtime), bukan cuma isi file. `tsk_recover`/`cat` nggak
  bakal nunjukin itu, harus `debugfs -R "stat"`.
- `crtime` itu timestamp paling susah dipalsuin di ext4 (nggak ada syscall standar, `stat` biasa
  nggak nampilin). Kalau `mtime`/`atime`/`ctime` seragam tapi `crtime` beda jauh, itu tanda
  anti-forensik.
- Buka image dengan mount bisa memicu journal replay yang ngubah metadata. Pakai `debugfs`
  read-only, jangan mount.
- `.bash_history` dihapus bukan berarti riwayat hilang. Di sini `.python_history` justru bocorin
  seluruh resep serangannya.
- Waspada pasangan umpan yang terlalu rapi (`BK_KEY` + `state.enc`). Verifikasi lewat tag GCM
  sebelum ngabisin waktu di situ.
