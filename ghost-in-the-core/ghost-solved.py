import struct
import re

def extract_pcap_payload(pcap_path):
    with open(pcap_path, "rb") as f:
        d = f.read()
    
    # Deteksi endianness pcap
    endian = ">" if d[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
    off = 24
    out = b""
    
    while off + 16 <= len(d):
        _t, _u, incl, _o = struct.unpack(endian + "IIII", d[off:off+16])
        pkt = d[off+16:off+16+incl]
        off += 16 + incl
        
        # Filter paket TCP valid yang memiliki payload
        if len(pkt) < 34 or pkt[23] != 6:
            continue
        
        ihl = (pkt[14] & 0x0f) * 4
        t = 14 + ihl
        if len(pkt) < t + 14:
            continue
            
        doff = (pkt[t + 12] >> 4) * 4
        pl = pkt[t + doff:]
        if pl:
            out += pl
            
    return out

def extract_env_salt(core_path):
    with open(core_path, "rb") as f:
        d = f.read()
    m = re.search(rb"GIO_LAUNCHED_DESKTOP_FILE=([ -~]+)", d)
    if not m:
        raise ValueError("GIO_LAUNCHED_DESKTOP_FILE tidak ditemukan di core dump.")
    
    env_str = m.group(1).decode("ascii").strip('\x00')
    # Ambil 16 karakter pertama format hex
    return env_str[:16]

def get_sensor_blobs(sensor_path):
    with open(sensor_path, "rb") as f:
        d = f.read()
    
    fixed_key = d[0x20d0:0x20d0 + 16]
    encrypted_config = d[0x2040:0x2040 + 37]
    return fixed_key, encrypted_config

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = bytearray()
    
    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
        
    # PRGA
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        out.append(byte ^ k)
        
    return bytes(out)

def main():
    print("[*] Membaca payload dari capture.pcap...")
    payload = extract_pcap_payload("capture.pcap")
    print(f"[+] Panjang payload jaringan terkumpul: {len(payload)} byte")

    print("[*] Mengekstrak salt env dari victim.core...")
    env_hex = extract_env_salt("victim.core")
    print(f"[+] Ditemukan env hex: {env_hex}")
    salt_bytes = bytes.fromhex(env_hex)

    print("[*] Membaca blob konstan dari binary sensor...")
    fixed_key, encrypted_config = get_sensor_blobs("sensor")

    # Rantai Kunci Pertama: 16 byte fixed + 8 byte salt (hasil decode env hex)
    key1 = fixed_key + salt_bytes
    print(f"[+] Panjang Kunci RC4-1: {len(key1)} byte")

    print("[*] Mendekripsi konfigurasi (Lapis 1)...")
    decrypted_config_bytes = rc4(key1, encrypted_config)
    
    try:
        config_str = decrypted_config_bytes.decode("utf-8")
    except UnicodeDecodeError:
        print("[-] Gagal mendatapkan teks UTF-8 yang valid. Kunci RC4-1 salah.")
        return

    print(f"[+] Config Terdekripsi: {config_str}")

    # Ekstraksi secret key (S=...) dari hasil konfigurasi
    match = re.search(r"S=([0-9a-fA-F]+)", config_str)
    if not match:
        print("[-] Parameter 'S=' tidak ditemukan dalam konfigurasi terdekripsi.")
        return
        
    secret_hex = match.group(1)
    print(f"[+] Ditemukan secret hex dari config: {secret_hex}")
    secret_bytes = bytes.fromhex(secret_hex)

    print("[*] Mendekripsi payload jaringan (Lapis 2)...")
    final_payload = rc4(secret_bytes, payload)

    try:
        flag = final_payload.decode("utf-8")
    except UnicodeDecodeError:
        print("[-] Payload akhir bukan format UTF-8 yang valid. Kunci RC4-2 salah.")
        return

    print("\n[+] BERHASIL! Hasil Dekripsi Akhir:")
    print(flag)

if __name__ == "__main__":
    main()
