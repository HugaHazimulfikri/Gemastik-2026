#!/usr/bin/env python3
"""
TZKS - GEMASTIK XIX 2026 Crypto (499)

Spesifikasi HLPSL-nya membocorkan dua cacat protokol sekaligus.

CACAT 1 - authorizer menerima commitment setelah menerbitkan tantangan.

    issue. State = 0 /\\ RCV(start)      =|> C0' := new() /\\ SND(C0')
    open.  State = 1 /\\ RCV(W0'.Z1'.Z2') /\\ add(mul(AA,Z1'), Z2') = add(W0, mul(C0,T))

  c0 dikirim lebih dulu, baru w diterima. Jadi w tidak mengikat apa pun dan bisa
  dipilih belakangan: ambil z1 = z2 = 0 lalu w = -c0*t, persamaan langsung pas.

CACAT 2 - nonce prover deterministik terhadap label.

    prove. Y' := MASK(S.E.Label')     <- hanya bergantung label
           C' := new()                <- selalu baru
           Z' := add(Y', mul(C', U'))

  Dua proof pada label yang sama memakai y identik dengan c berbeda, sehingga
  z1 - z2 = (c1 - c2) * u  membocorkan u = <a_label, s>. Cukup empat label
  untuk menyusun sistem linier dan memulihkan s seutuhnya.

Dengan s di tangan, e = t - A*s, dan auth bisa dijawab secara jujur dengan z
yang normanya kecil sehingga lolos pengecekan verifier.

Butuh: numpy. Jalankan: python3 solve.py
"""
import hashlib
import itertools
import json
import socket
import sys

import numpy as np

HOST, PORT = "15.232.64.175", 13500
NUM_LABELS = 4          # butuh l = 4 label untuk menentukan s secara unik


# --------------------------------------------------------------------------
# Encoding wire dan aritmetika ring R_q = Z_q[x]/(x^n + 1)
# --------------------------------------------------------------------------
def unpack(h, n):
    raw = bytes.fromhex(h)
    return [int.from_bytes(raw[3 * i:3 * i + 3], "big") for i in range(n)]


def pack(coeffs):
    return b"".join(int(c % (1 << 24)).to_bytes(3, "big") for c in coeffs).hex()


def pmul(f, g, q, n):
    out = [0] * n
    for i, fi in enumerate(f):
        if not fi:
            continue
        for j, gj in enumerate(g):
            if not gj:
                continue
            kk = i + j
            if kk < n:
                out[kk] = (out[kk] + fi * gj) % q
            else:                                  # x^n = -1
                out[kk - n] = (out[kk - n] - fi * gj) % q
    return out


def padd(f, g, q):
    return [(a + b) % q for a, b in zip(f, g)]


def psub(f, g, q):
    return [(a - b) % q for a, b in zip(f, g)]


def negacyclic_matrix(c, n, q):
    """Matriks M sehingga (c * u)[k] = sum_j M[k][j] * u[j] di R_q."""
    M = np.zeros((n, n), dtype=np.int64)
    for kk in range(n):
        for j in range(n):
            M[kk][j] = c[kk - j] % q if kk >= j else (-c[kk - j + n]) % q
    return M


def centered(x, q):
    return x - q if x > q // 2 else x


# --------------------------------------------------------------------------
# Eliminasi Gauss mod q (q prima)
# --------------------------------------------------------------------------
def solve_mod(M, b, q):
    M = M.astype(np.int64) % q
    b = b.astype(np.int64) % q
    m, ncol = M.shape
    aug = np.concatenate([M, b.reshape(-1, 1)], axis=1)
    row = 0
    where = []
    for col in range(ncol):
        piv = None
        for r in range(row, m):
            if aug[r][col]:
                piv = r
                break
        if piv is None:
            continue
        aug[[row, piv]] = aug[[piv, row]]
        inv = pow(int(aug[row][col]), q - 2, q)
        aug[row] = (aug[row] * inv) % q
        nz = np.nonzero(aug[:, col])[0]
        nz = nz[nz != row]
        if len(nz):
            aug[nz] = (aug[nz] - np.outer(aug[nz, col], aug[row])) % q
        where.append(col)
        row += 1
        if row == m:
            break
    if len(where) < ncol:
        return None                       # sistem belum menentukan solusi unik
    x = np.zeros(ncol, dtype=np.int64)
    for i, col in enumerate(where):
        x[col] = aug[i][-1]
    return x


# --------------------------------------------------------------------------
def solve_pow(chal, bits):
    for i in itertools.count():
        s = str(i)
        if int.from_bytes(hashlib.sha256((chal + s).encode()).digest(), "big") >> (256 - bits) == 0:
            return s


def main():
    print(f"[*] Menyambung ke {HOST}:{PORT} ...")
    sock = socket.create_connection((HOST, PORT), timeout=30)
    sock.settimeout(300)
    f = sock.makefile("rwb")
    send = lambda o: (f.write((json.dumps(o) + "\n").encode()), f.flush())

    def recv():
        line = f.readline()
        if not line:
            sys.exit("[-] koneksi ditutup server")
        return json.loads(line)

    pw = recv()["pow"]
    print(f"[*] Proof-of-work {pw['bits']} bit ...")
    send({"pow": solve_pow(pw["chal"], pw["bits"])})

    p = recv()
    n, q, k, l = p["n"], p["q"], p["k"], p["l"]
    eta, gamma, tau = p["eta"], p["gamma"], p["tau"]
    print(f"[+] n={n} q={q} k={k} l={l} eta={eta} gamma={gamma} tau={tau}")
    A = [[unpack(h, n) for h in row] for row in p["A"]]
    t = [unpack(h, n) for h in p["t"]]

    # ---- CACAT 1: lolos enroll tanpa tahu apa pun ------------------------
    print("[*] Enroll: minta c0 dulu, baru susun w yang cocok ...")
    send({"cmd": "enroll"})
    c0 = unpack(recv()["c0"], n)
    zero_l = [[0] * n for _ in range(l)]
    zero_k = [[0] * n for _ in range(k)]
    w0 = [[(-x) % q for x in pmul(c0, t[i], q, n)] for i in range(k)]   # w = -c0*t
    send({"cmd": "enroll_open",
          "w": [pack(x) for x in w0],
          "z1": [pack(x) for x in zero_l],
          "z2": [pack(x) for x in zero_k]})
    if not recv().get("ok"):
        sys.exit("[-] enroll ditolak")
    print("[+] Terotorisasi tanpa kredensial apa pun")

    # ---- CACAT 2: bocorkan u = <a,s> lewat nonce yang dipakai ulang ------
    print(f"[*] Mengumpulkan {NUM_LABELS} label, masing-masing dua proof ...")
    rows, rhs = [], []
    for idx in range(NUM_LABELS):
        label = f"{idx:016x}"
        proofs = []
        for _ in range(2):
            send({"cmd": "prove", "label": label})
            r = recv()
            if "z" not in r:
                sys.exit(f"[-] prove gagal: {r}")
            proofs.append(r)
        assert proofs[0]["w"] == proofs[1]["w"], "w berbeda, nonce ternyata acak"

        a = [unpack(h, n) for h in proofs[0]["a"]]
        dc = psub(unpack(proofs[0]["c"], n), unpack(proofs[1]["c"], n), q)
        dz = psub(unpack(proofs[0]["z"], n), unpack(proofs[1]["z"], n), q)

        u = solve_mod(negacyclic_matrix(dc, n, q), np.array(dz), q)
        if u is None:
            sys.exit("[-] c1 - c2 tidak invertibel, ulangi")
        print(f"[+] label {label}: u = <a,s> berhasil dipulihkan")

        blk = np.concatenate([negacyclic_matrix(a[i], n, q) for i in range(l)], axis=1)
        rows.append(blk)
        rhs.append(u)

    print("[*] Menyusun sistem linier untuk s ...")
    M = np.concatenate(rows, axis=0)
    b = np.concatenate(rhs, axis=0)
    sv = solve_mod(M, b, q)
    if sv is None:
        sys.exit("[-] sistem singular, tambah jumlah label")
    s_vec = [list(sv[i * n:(i + 1) * n]) for i in range(l)]
    mx = max(abs(centered(int(x), q)) for poly in s_vec for x in poly)
    print(f"[+] s dipulihkan, norma tak hingga = {mx} (eta = {eta})")

    e_vec = []
    for i in range(k):
        acc = [0] * n
        for j in range(l):
            acc = padd(acc, pmul(A[i][j], s_vec[j], q, n), q)
        e_vec.append(psub(t[i], acc, q))
    me = max(abs(centered(int(x), q)) for poly in e_vec for x in poly)
    print(f"[+] e = t - A*s, norma tak hingga = {me} (eta = {eta})")

    # ---- Auth secara jujur, sekarang z-nya kecil dan lolos batas norma ---
    print("[*] Auth dengan proof yang sah ...")
    bound = gamma - tau * eta - 64
    rng = np.random.default_rng(1337)
    y1 = [[int(v) % q for v in rng.integers(-bound, bound, n)] for _ in range(l)]
    y2 = [[int(v) % q for v in rng.integers(-bound, bound, n)] for _ in range(k)]
    w = []
    for i in range(k):
        acc = list(y2[i])
        for j in range(l):
            acc = padd(acc, pmul(A[i][j], y1[j], q, n), q)
        w.append(acc)

    send({"cmd": "auth", "w": [pack(x) for x in w]})
    r = recv()
    if "c" not in r:
        sys.exit(f"[-] auth gagal: {r}")
    c = unpack(r["c"], n)

    z1 = [padd(y1[j], pmul(c, s_vec[j], q, n), q) for j in range(l)]
    z2 = [padd(y2[i], pmul(c, e_vec[i], q, n), q) for i in range(k)]
    mz = max(abs(centered(int(x), q)) for poly in z1 + z2 for x in poly)
    print(f"[+] norma tak hingga z = {mz} (batas gamma = {gamma})")

    send({"cmd": "auth_resp", "z1": [pack(x) for x in z1], "z2": [pack(x) for x in z2]})
    resp = recv()
    if "flag" in resp:
        print(f"[+] FLAG: {resp['flag']}")
    else:
        print(f"[-] gagal: {resp}")
    sock.close()


if __name__ == "__main__":
    main()
