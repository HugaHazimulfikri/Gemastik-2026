import gzip
import hashlib
import io
import re
import subprocess
import sys
import tarfile
from Crypto.Cipher import AES

IMAGE_FILE = 'fin-ws-04.img'


def run_debugfs_text(command):
  cmd = ['debugfs', '-R', command, IMAGE_FILE]
  result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
  if result.returncode != 0 and 'Extended attributes' not in result.stdout:
    print(f"[!] debugfs error for command '{command}': {result.stderr}")
  return result.stdout


def run_debugfs_binary(command):
  cmd = ['debugfs', '-R', command, IMAGE_FILE]
  result = subprocess.run(cmd, capture_output=True)
  if result.returncode != 0:
    print(f"[!] debugfs binary error for command '{command}': {result.stderr}")
  return result.stdout


def main():
  print(
      '[*] Step 1: Extracting UPLOAD_ID from cron configuration'
      ' (/etc/cron.d/geoclue-refresh)...'
  )
  cron_content = run_debugfs_text('cat /etc/cron.d/geoclue-refresh')
  match = re.search(r'UPLOAD_ID=([a-zA-Z0-9]+)', cron_content)
  if not match:
    print('[!] UPLOAD_ID not found in the cron configuration file!')
    sys.exit(1)
  upload_id = match.group(1)
  print(f'[+] Successfully extracted UPLOAD_ID: {upload_id}')

  print(
      '[*] Step 2: Inspecting tool metadata (inode, timestamps, xattr) via'
      ' debugfs stat...'
  )
  stat_output = run_debugfs_text(
      'stat /usr/local/sbin/systemd-timesyncd-helper'
  )

  # Parse Inode dynamically
  inode_match = re.search(r'Inode:\s+(\d+)', stat_output)
  inode_num = inode_match.group(1) if inode_match else 'Unknown'
  print(f'[+] Target file Inode resolved dynamically: {inode_num}')

  # Parse mtime and crtime
  mtime_match = re.search(r'mtime:\s+0x([0-9a-fA-F]+):', stat_output)
  crtime_match = re.search(r'crtime:\s+0x([0-9a-fA-F]+):', stat_output)

  if not mtime_match or not crtime_match:
    print('[!] Failed to parse mtime or crtime from debugfs stat output!')
    sys.exit(1)

  mtime_epoch = int(mtime_match.group(1), 16)
  crtime_epoch = int(crtime_match.group(1), 16)

  print('\n----------------------------------------')
  print('           TIMESTAMP ANALYSIS           ')
  print('----------------------------------------')
  print(
      f'[*] mtime  : {mtime_epoch} (Hex: 0x{mtime_match.group(1)}) -> [FORGED'
      ' / TOUCHED]'
  )
  print(
      f'[*] crtime : {crtime_epoch} (Hex: {crtime_match.group(1)}) -> [REAL'
      ' / UNALTERED BIRTH TIME]'
  )
  print('----------------------------------------\n')

  # Parse part_b from extended attributes
  xattr_match = re.search(r'user\.upl_b\s*\(\d+\)\s*=\s*"([^"]+)"', stat_output)
  if not xattr_match:
    print(
        '[!] Failed to parse extended attribute user.upl_b from inode'
        ' metadata!'
    )
    sys.exit(1)
  part_b = xattr_match.group(1)
  print(f'[+] Successfully extracted part_b from xattr: {part_b}')

  print(
      '[*] Step 3: Deriving Vault Key using PBKDF2-HMAC-SHA256 (200,000'
      ' iterations)...'
  )
  password = (upload_id + part_b).encode('utf-8')
  salt = str(crtime_epoch).encode('utf-8')
  iterations = 200000
  key_length = 32

  derived_key = hashlib.pbkdf2_hmac(
      'sha256', password, salt, iterations, dklen=key_length
  )
  print(f'[+] Derived Key (Hex): {derived_key.hex()}')

  print(
      '[*] Step 4: Extracting encrypted vault payload'
      ' (/var/tmp/.ICE-unix/1000/.cache-dwi.dat)...'
  )
  encrypted_data = run_debugfs_binary(
      'cat /var/tmp/.ICE-unix/1000/.cache-dwi.dat'
  )
  if not encrypted_data or len(encrypted_data) < 28:
    print(
        '[!] Failed to extract encrypted file or payload size is too small!'
    )
    sys.exit(1)
  print(
      f'[+] Successfully extracted encrypted payload ({len(encrypted_data)}'
      ' bytes)'
  )

  print(
      '[*] Step 5: Decrypting and verifying payload with AES-GCM (Nonce: 12 bytes,'
      ' Tag: 16 bytes)...'
  )
  nonce = encrypted_data[:12]
  tag = encrypted_data[-16:]
  ciphertext = encrypted_data[12:-16]

  try:
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    decrypted_gzip = cipher.decrypt_and_verify(ciphertext, tag)
    print('[+] AES-GCM Decryption successful! Cryptographic tag verified.')
  except ValueError as e:
    print(
        '[!] GCM Tag verification failed! The derived key or ciphertext is'
        ' incorrect.'
    )
    print(f'    Error details: {e}')
    sys.exit(1)

  print(
      '[*] Step 6: Inspecting archive contents safely in memory (no disk'
      ' writes)...'
  )
  try:
    decompressed_gzip = gzip.decompress(decrypted_gzip)
    flag_pattern = re.compile(r'GEMASTIK19\{[^}]*\}')
    found_flags = []

    with tarfile.open(fileobj=io.BytesIO(decompressed_gzip), mode='r') as tar:
      for member in tar.getmembers():
        print(f'\n--- File: {member.name} (Size: {member.size} bytes) ---')
        if member.isfile():
          f = tar.extractfile(member)
          if f:
            content_bytes = f.read()
            try:
              content_text = content_bytes.decode('utf-8')
              print(content_text)

              # Step 7: Search for flag with line numbers
              lines = content_text.splitlines()
              for line_idx, line in enumerate(lines, 1):
                match = flag_pattern.search(line)
                if match:
                  found_flags.append((match.group(0), member.name, line_idx))
            except UnicodeDecodeError:
              print(
                  '[!] Binary file or non-text content, skipping direct text'
                  ' display.'
              )
        else:
          print('[Directory or special entry]')

    print('\n----------------------------------------')
    print('           FLAG SEARCH RESULTS          ')
    print('----------------------------------------')
    if found_flags:
      for flag, filename, lineno in found_flags:
        print(f'[+] FLAG FOUND: {flag}')
        print(f'    File Path  : {filename}')
        print(f'    Line Number: {lineno}')
    else:
      print('[!] Flag pattern not found in any of the extracted archive files.')
    print('----------------------------------------')

  except Exception as e:
    print(f'[!] Failed during gzip decompression or archive inspection: {e}')
    sys.exit(1)


if __name__ == '__main__':
  main()
