def solve_ctf():
    # Ciphertext yang diberikan (cipher.txt)
    with open("cipher.txt") as f:
        ciphertext = f.read().strip()

    # 1. Validasi Marker Start & End
    if not (ciphertext.startswith('S') and ciphertext.endswith('Z')):
        print("[-] Peringatan: Marker awal atau akhir tidak sesuai.")

    # Hilangkan huruf 'S' di awal dan 'Z' di akhir
    core_data = ciphertext[1:-1]

    # 2. Split berdasarkan delimiter "DW"
    blocks = core_data.split("DW")

    binary_chars = []

    # 3. Proses setiap blok (O = 1, H = 0)
    for block in blocks:
        if not block:
            continue
        # Ganti 'O' dengan '1' dan 'H' dengan '0'
        bin_str = block.replace('O', '1').replace('H', '0')

        # Konversi string biner ke integer, lalu ke karakter ASCII
        decimal_val = int(bin_str, 2)
        binary_chars.append(chr(decimal_val))

    # Gabungkan menjadi string Hex awal
    hex_string = "".join(binary_chars)
    print(f"[+] Hex String: {hex_string}")

    # 4. Decode dari Hex ke string teks asli (flag)
    try:
        flag = bytes.fromhex(hex_string).decode('utf-8')
        print(f"[+] Flag Berhasil Didapatkan: {flag}")
    except Exception as e:
        print(f"[-] Gagal melakukan decode hex ke ASCII: {e}")

if __name__ == "__main__":
    solve_ctf()
