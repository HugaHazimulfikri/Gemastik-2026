# Ecliprime - GEMASTIK XIX 2026 Crypto (500)
# RSA 1024-bit dengan 312 bit teratas dari p bocor. 200 bit sisanya dipulihkan
# dengan Coppersmith (batas teoretis untuk p 512-bit adalah 256 bit, jadi lapang).
import importlib.util, hashlib
from Crypto.Cipher import AES

spec = importlib.util.spec_from_file_location("chal", "challenge.py")
chal = importlib.util.module_from_spec(spec); spec.loader.exec_module(chal)

N, e, M, p_high = Integer(chal.N), chal.e, chal.M, Integer(chal.p_high)
print(f"[*] N {N.nbits()} bit, p_high {p_high.nbits()} bit, {M} bit tak diketahui")
assert p_high % (2**M) == 0, "p_high seharusnya punya M bit nol di bawah"

# f(x) = p_high + x  (mod N), akar kecil x < 2^M memberi faktor p
PR = PolynomialRing(Zmod(N), 'x')
x = PR.gen()
f = (p_high + x).monic()

print("[*] Coppersmith small_roots ...")
roots = f.small_roots(X=2**M, beta=0.4, epsilon=0.02)
if not roots:
    raise SystemExit("[-] tidak ada akar; naikkan beta/epsilon")

p = p_high + Integer(roots[0])
assert N % p == 0, "[-] p bukan faktor N"
q = N // p
print(f"[+] p = {p}")
print(f"[+] q = {q}")
print(f"[+] p*q == N: {p*q == N}")

key = chal.derive_key(int(p))
print(f"[+] AES key = {key.hex()}")
c = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(chal.flag_enc["nonce"]))
flag = c.decrypt_and_verify(bytes.fromhex(chal.flag_enc["ciphertext"]),
                            bytes.fromhex(chal.flag_enc["tag"]))
print(f"[+] FLAG: {flag.decode()}")
