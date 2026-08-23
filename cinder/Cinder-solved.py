#!/usr/bin/env python3
import os
import struct
import base64
import hashlib
import sqlite3
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES

def parse_secure_prefs(xml_path):
    """Membaca parameter kripto secara dinamis dari secure_prefs.xml."""
    print(f"[*] Membaca konfigurasi dari: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()
    prefs = {}
    for elem in root:
        name = elem.get("name")
        if elem.tag == "string":
            prefs[name] = elem.text
        elif elem.tag == "int":
            prefs[name] = int(elem.get("value"))
        elif elem.tag == "boolean":
            prefs[name] = elem.get("value") == "true"
        elif elem.tag == "long":
            prefs[name] = int(elem.get("value"))
    return prefs

def parse_protobuf_blob(blob):
    """Parser sederhana untuk Protobuf wire type 2 (length-delimited) pada body pesan."""
    fields = {}
    pos = 0
    while pos < len(blob):
        tag_byte = blob[pos]
        pos += 1
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07
        if wire_type == 2:
            length = 0
            shift = 0
            while True:
                b = blob[pos]
                pos += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            value = blob[pos:pos + length]
            pos += length
            fields[field_num] = value
        else:
            break
    return fields

def main():
    db_path = "com.example.cinder/databases/chat.db"
    wal_path = "com.example.cinder/databases/chat.db-wal"
    prefs_path = "com.example.cinder/shared_prefs/secure_prefs.xml"

    if not all(os.path.exists(p) for p in [db_path, wal_path, prefs_path]):
        print("[-] Error: File artefak Cinder tidak lengkap di direktori ini.")
        return

    # 1. Ambil parameter kripto dari XML
    prefs = parse_secure_prefs(prefs_path)
    install_key = base64.b64decode(prefs["install_key"])
    kdf_salt = base64.b64decode(prefs["kdf_salt"])
    kdf_iters = prefs["kdf_iters"]

    # Turunkan kunci AES-256 menggunakan PBKDF2
    key = hashlib.pbkdf2_hmac("sha256", install_key, kdf_salt, kdf_iters, dklen=32)
    print("[+] Kunci enkripsi berhasil diturunkan via PBKDF2.")

    # 2. BACA FILE SEBAGAI BYTES (PENGAMANAN BARANG BUKTI)
    # PENTING: Jangan pernah membuka file chat.db asli langsung menggunakan sqlite3.connect()
    # karena koneksi SQLite dapat memicu operasi checkpoint otomatis atau mengubah file WAL/SHM asli,
    # yang akan merusak integritas barang bukti digital.
    with open(db_path, "rb") as f:
        base_db_bytes = f.read()

    with open(wal_path, "rb") as f:
        wal_bytes = f.read()

    # 3. Parse Header WAL secara Dinamis
    # Offset 8 pada header WAL menyimpan ukuran halaman (page size)
    page_size = struct.unpack(">I", wal_bytes[8:12])[0]
    header_size = 32
    frame_header_size = 24
    frame_total_size = frame_header_size + page_size

    num_frames = (len(wal_bytes) - header_size) // frame_total_size
    print(f"[*] Ukuran Halaman (Page Size) terdeteksi: {page_size} bytes")
    print(f"[*] Total Frame di WAL terdeteksi: {num_frames} frames")

    # 4. Ekstraksi Frame dan Deteksi Batas Transaksi
    frames = []
    transactions = []
    current_tx_frames = []

    for i in range(num_frames):
        offset = header_size + i * frame_total_size
        f_hdr = wal_bytes[offset:offset + frame_header_size]
        f_data = wal_bytes[offset + frame_header_size:offset + frame_total_size]
        
        pgno, dbsize = struct.unpack(">II", f_hdr[0:8])
        current_tx_frames.append((pgno, f_data))
        
        # Field dbsize > 0 menandakan akhir dari sebuah transaksi (Commit Frame)
        if dbsize > 0:
            transactions.append(list(current_tx_frames))
            current_tx_frames = []

    print(f"[*] Total Transaksi ditemukan dalam WAL: {len(transactions)}")

    if len(transactions) == 0:
        print("[-] Tidak ditemukan transaksi commit di dalam file WAL.")
        return

    # 5. Rekonstruksi State Database per Transaksi & Dekripsi Pesan
    all_tx_messages = []

    for tx_idx in range(len(transactions)):
        # Akumulasi frame secara sekuensial hingga transaksi saat ini
        cumulative_frames = []
        for t_i in range(tx_idx + 1):
            cumulative_frames.extend(transactions[t_i])

        # Rakit ulang halaman database di memori
        pages = {}
        for idx in range(len(base_db_bytes) // page_size):
            pages[idx + 1] = base_db_bytes[idx * page_size : (idx + 1) * page_size]
        
        for pgno, f_data in cumulative_frames:
            pages[pgno] = f_data

        max_pg = max(pages.keys())
        temp_db_bytes = bytearray()
        for p in range(1, max_pg + 1):
            temp_db_bytes.extend(pages.get(p, b"\x00" * page_size))

        # Tulis ke file sementara HANYA untuk dibaca oleh modul sqlite3 secara aman, lalu hapus
        temp_filename = f"_temp_forensic_tx_{tx_idx}.db"
        with open(temp_filename, "wb") as tf:
            tf.write(bytes(temp_db_bytes))

        try:
            conn = sqlite3.connect(temp_filename)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages';")
            if not cursor.fetchone():
                conn.close()
                os.remove(temp_filename)
                continue

            cursor.execute("SELECT id, thread, ts, body FROM messages ORDER BY id;")
            rows = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"[-] Error membaca database sementara untuk transaksi {tx_idx}: {e}")
            rows = []
        finally:
            if os.path.exists(temp_filename):
                os.remove(temp_filename)

        # Proses dan dekripsi pesan
        tx_msgs = []
        for rowid, thread, ts, body_blob in rows:
            fields = parse_protobuf_blob(body_blob)
            sender = fields.get(1, b"").decode("utf-8", errors="ignore")
            nonce = fields.get(2, b"")
            ciphertext = fields.get(3, b"")
            tag = fields.get(4, b"")

            plaintext = "[DEKRIPSI GAGAL]"
            if nonce and ciphertext and tag:
                try:
                    # Menggunakan pola AAD dinamis: f"{thread}:{rowid}"
                    aad = f"{thread}:{rowid}".encode("utf-8")
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    cipher.update(aad)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8", errors="ignore")
                except Exception as ex:
                    plaintext = f"[ERROR KRI PTO: {ex}]"

            tx_msgs.append({
                "id": rowid,
                "thread": thread,
                "ts": ts,
                "sender": sender,
                "message": plaintext
            })
        
        all_tx_messages.append(tx_msgs)

    # 6. Cetak Hasil Analisis Perbandingan Transaksi
    print("\n" + "="*60)
    print(" LAPORAN ANALISIS FORENSIK: REKONSTRUKSI WAL CINDER ")
    print("="*60)

    for idx, msgs in enumerate(all_tx_messages):
        print(f"\n[+] State Database pada Transaksi ke-{idx + 1} ({len(msgs)} pesan):")
        for m in msgs:
            print(f"    - ID: {m['id']} | Thread: {m['thread']} | Pengirim: {m['sender']} | Pesan: {m['message']}")

    # Bandingkan state awal dan akhir untuk mencari pesan yang terhapus
    if len(all_tx_messages) >= 2:
        latest_ids = {m['id'] for m in all_tx_messages[-1]}
        deleted_messages = [m for m in all_tx_messages[0] if m['id'] not in latest_ids]
        
        print("\n" + "-"*60)
        print("[!] TEMUAN UTAMA: PESAN YANG DIHAPUS PADA TRANSAKSI BERIKUTNYA")
        print("-"*60)
        if deleted_messages:
            for m in deleted_messages:
                print(f"    [DITEMUKAN DI WAL WALKBACK] ID: {m['id']} | Thread: {m['thread']} | Pengirim: {m['sender']} | Pesan: {m['message']}")
        else:
            print("    Tidak ada pesan unik yang ditemukan di state lampau.")
    else:
        print("\n[-] WAL hanya memiliki satu transaksi, tidak ada data historis yang bisa dibandingkan.")

if __name__ == "__main__":
    main()
