#!/usr/bin/env python3

import hashlib
from Crypto.Cipher import AES

N = 83711328797097213763431917143724719880328286831374494916391870463804082497622817924257066620857447664956912331024462634450073401382090940211890547198128442765199146868198034842075476655389487735451454958408610110235842833015536345386400702600407606917678951121781451005120025926791201300875034875989541238363
e = 65537

M = 200
p_high = 7790664985083616370391324797496932612736652613564010012569243844532923193953990001739616546188299729447871377719498947043779822920348951560395136182517760

oaep_ciphertext = "48569ef0a9728558c910ad25906be4841526e935241f1e4420d61d5077cead2ea84803f045062d297c942156578288882055da772c4c88f8a980c76c8e3689fff81d12e77baac959f506bee74cf6d0dc219acbd1a3bbe0ab17ef6927f9fc2e55527c27b4ab980849c09bcff720ccfef7367b7701ac8f262cb44707d5452c26e8"

flag_enc = {
    "cipher": "AES-256-GCM",
    "nonce": "707744b6d7c44b5cf3c97a1c75106ef0",
    "ciphertext": "8e44d3115874d057a22049cd05f3948803ff4cba5e99e66e318bc199d26098b515ef1c58b3b95249711ad5bf136d1fb1ede08511d2e34c7eeedaa8",
    "tag": "f8dda3f1501906d30b7c8024ad724d9f",
}

DOMAIN = b"prime-eclipse::v2::attestation-root::(p_small,dp)"
KDF_SALT = hashlib.sha256(b"prime-eclipse::stage::standalone").digest()
KDF_INFO = b"prime-eclipse|flag|aes256gcm"


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    key = key.ljust(64, b"\x00")
    o = bytes(b ^ 0x5C for b in key)
    i = bytes(b ^ 0x36 for b in key)
    return hashlib.sha256(o + hashlib.sha256(i + msg).digest()).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if salt == b"":
        salt = b"\x00" * 32
    prk = _hmac_sha256(salt, ikm)
    okm, t, c = b"", b"", 1
    while len(okm) < length:
        t = _hmac_sha256(prk, t + info + bytes([c]))
        okm += t
        c += 1
    return okm[:length]


def derive_key(p: int) -> bytes:
    q = N // p
    assert p * q == N
    d = pow(e, -1, (p - 1) * (q - 1))
    p_small = min(p, q)
    dp = d % (p_small - 1)
    ikm = hashlib.sha256(
        DOMAIN + p_small.to_bytes(64, "big") + dp.to_bytes(64, "big")
    ).digest()
    return hkdf_sha256(ikm, KDF_SALT, KDF_INFO, 32)


def seal_flag(p: int, flag: bytes) -> dict:
    key = derive_key(p)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(flag)
    return {
        "cipher": "AES-256-GCM",
        "nonce": cipher.nonce.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
    }
