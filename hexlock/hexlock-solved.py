import subprocess
import re
from Crypto.Cipher import AES

def va_to_file(va):
    """
    Konversi Virtual Address (VA) ke File Offset berdasarkan peta section biner:
    .rodata    : VA 0x4ae000, file 0xae000
    .noptrdata : VA 0x567040, file 0x167040
    .data      : VA 0x56efc0, file 0x16efc0
    Delta konsisten untuk section-section ini adalah 0x400000.
    """
    return va - 0x400000

print("[*] Membaca biner 'hexlock'...")
with open("hexlock", "rb") as f:
    binary_data = f.read()

# 1. Membaca Nonce dari VA 0x567148 (panjang 12 byte)
nonce_file_offset = va_to_file(0x567148)
nonce = binary_data[nonce_file_offset:nonce_file_offset + 12]
print(f"[+] Nonce berhasil dibaca ({len(nonce)} byte): {nonce.hex()}")

# 2. Membaca Header {ptr, len} di VA 0x56f490 (16 byte: 8 byte pointer + 8 byte length)
header_file_offset = va_to_file(0x56f490)
header_bytes = binary_data[header_file_offset:header_file_offset + 16]
blob_ptr = int.from_bytes(header_bytes[0:8], byteorder='little')
blob_len = int.from_bytes(header_bytes[8:16], byteorder='little')
print(f"[+] Blob Pointer (VA): {hex(blob_ptr)}, Total Panjang Blob: {blob_len} byte")

# Membaca data blob menggunakan pointer VA yang dikonversi ke file offset
blob_file_offset = va_to_file(blob_ptr)
blob_data = binary_data[blob_file_offset:blob_file_offset + blob_len]

# Panjang flag diturunkan dari total panjang blob dikurangi tag GCM (16 byte)
flag_len = blob_len - 16
print(f"[+] Panjang flag yang disimpulkan: {flag_len} karakter")

ciphertext = blob_data[:-16]
tag = blob_data[-16:]

# 3. Mengambil base key melalui GDB subprocess
print("[*] Menjalankan GDB untuk mengambil base key...")
gdb_cmd = [
    "gdb", "-batch", "-nx",
    "-ex", "break *0x4acd77",
    "-ex", "run 'GEMASTIK19{test}'",
    "-ex", "x/16bx $rax",
    "./hexlock"
]
gdb_result = subprocess.run(gdb_cmd, capture_output=True, text=True)

# Parsing nilai hex secara ketat hanya dari baris memori GDB (setelah tanda ':')
base_key_bytes = []
for line in gdb_result.stdout.splitlines():
    if ":" in line:
        # Ambil bagian setelah tanda titik dua untuk menghindari alamat memori
        data_part = line.split(":", 1)[1]
        matches = re.findall(r'0x[0-9a-fA-F]{2}', data_part)
        for m in matches:
            base_key_bytes.append(int(m, 16))

if len(base_key_bytes) < 16:
    print("[-] Gagal mengekstrak key dari output GDB!")
    print(gdb_result.stdout)
    exit(1)

# Ambil tepat 16 byte terakhir
base_key_bytes = base_key_bytes[-16:]
base_key = bytearray(base_key_bytes)

print(f"[+] Base key dari GDB: {base_key.hex()}")
print("    [CATATAN PENTING: Kunci di atas UDAH TERKORUPSI karena mekanisme anti-debug / TracerPid]")
print("    [                saat GDB melampirkan diri. Kita menggunakan kunci ini sebagai base       ]")
print("    [                untuk brute-force perbaikan byte.]")

# 4. Brute-force semua 16 posisi x 256 kemungkinan nilai byte (4096 kombinasi total)
print("[*] Memulai brute-force 4096 kombinasi key untuk verifikasi GCM...")
correct_plaintext = None
found = False

for pos in range(16):
    original_byte = base_key[pos]
    for b in range(256):
        base_key[pos] = b
        try:
            cipher = AES.new(bytes(base_key), AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            correct_plaintext = plaintext
            found = True
            print(f"[+] Kunci valid ditemukan! Posisi byte ke-{pos} diubah ke {hex(b)}")
            break
        except ValueError:
            # GCM autentikasi gagal (tag mismatch)
            continue
    if found:
        break
    # Kembalikan ke byte semula jika posisi ini bukan sumber masalah
    base_key[pos] = original_byte

if not found or not correct_plaintext:
    print("[-] Brute-force gagal: Tidak ada kombinasi kunci yang lolos verifikasi tag GCM.")
    exit(1)

flag = correct_plaintext.decode()
print(f"[+] Flag berhasil didekripsi: {flag}")

# 5. Verifikasi otomatis dengan menjalankan binary ./hexlock lewat subprocess
print("[*] Melakukan verifikasi otomatis dengan mengeksekusi binary...")
run_res = subprocess.run(["./hexlock", flag], capture_output=True, text=True)
binary_output = run_res.stdout + run_res.stderr
print(f"[+] Output biner:\n{binary_output.strip()}")

if "Correct!" in binary_output:
    print("[SUKSES] Flag terverifikasi 100% BENAR oleh program asli!")
else:
    print("[-] Peringatan: Dekripsi GCM berhasil, namun biner tidak mencetak 'Correct!'.")
