#!/usr/bin/env python3
import getpass
import hmac as hmac_module
import hashlib
import json
import os
import secrets
import struct
import sys
from typing import Dict, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

VAULT_DIR = ".vault"
INDEX_FILE = os.path.join(VAULT_DIR, "index.json")

MAGIC = b"SVLT"
VERSION = 1
SALT_LEN = 16
IV_LEN = 16
TAG_LEN = 32
ENC_KEY_LEN = 32
MAC_KEY_LEN = 32
PBKDF2_ITERATIONS = 600_000
HEADER_STRUCT = struct.Struct(">4sB I")  # magic, version, PBKDF2 iteration count


class VaultError(Exception):
    pass


def derive_keys(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> Tuple[bytes, bytes]:
    """Derive independent encryption and authentication keys from one PBKDF2 call."""
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=ENC_KEY_LEN + MAC_KEY_LEN,
    )
    return key_material[:ENC_KEY_LEN], key_material[ENC_KEY_LEN:]


def load_index() -> Dict[str, str]:
    if not os.path.exists(INDEX_FILE):
        return {}
    with open(INDEX_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_index(index: Dict[str, str]) -> None:
    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp = INDEX_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, sort_keys=True)
    os.replace(tmp, INDEX_FILE)


def make_blob(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    k_enc, k_mac = derive_keys(password, salt)

    cipher = AES.new(k_enc, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    header = HEADER_STRUCT.pack(MAGIC, VERSION, PBKDF2_ITERATIONS) + salt + iv
    tag = hmac_module.new(k_mac, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def open_blob(blob: bytes, password: str) -> bytes:
    min_len = HEADER_STRUCT.size + SALT_LEN + IV_LEN + AES.block_size + TAG_LEN
    if len(blob) < min_len:
        raise VaultError("stored blob is too short")

    header_prefix = blob[:HEADER_STRUCT.size]
    try:
        magic, version, iterations = HEADER_STRUCT.unpack(header_prefix)
    except struct.error as exc:
        raise VaultError("stored blob header is invalid") from exc

    if magic != MAGIC or version != VERSION:
        raise VaultError("stored blob format is unsupported")
    if iterations <= 0:
        raise VaultError("stored blob contains an invalid KDF iteration count")

    salt_start = HEADER_STRUCT.size
    iv_start = salt_start + SALT_LEN
    ciphertext_start = iv_start + IV_LEN
    tag_start = len(blob) - TAG_LEN

    salt = blob[salt_start:iv_start]
    iv = blob[iv_start:ciphertext_start]
    ciphertext = blob[ciphertext_start:tag_start]
    stored_tag = blob[tag_start:]

    if len(salt) != SALT_LEN or len(iv) != IV_LEN or len(ciphertext) == 0:
        raise VaultError("stored blob is malformed")
    if len(ciphertext) % AES.block_size != 0:
        raise VaultError("stored ciphertext length is invalid")

    k_enc, k_mac = derive_keys(password, salt, iterations)
    computed_tag = hmac_module.new(k_mac, blob[:tag_start], hashlib.sha256).digest()
    if not hmac_module.compare_digest(stored_tag, computed_tag):
        raise VaultError("wrong password or corrupted file")

    cipher = AES.new(k_enc, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError as exc:
        # This should be unreachable after a valid HMAC, but keeps failures clear.
        raise VaultError("stored ciphertext padding is invalid") from exc


def blob_name_for(filename: str, index: Dict[str, str]) -> str:
    if filename in index:
        return index[filename]
    return secrets.token_hex(16) + ".bin"


def cmd_add(filename: str) -> None:
    if not os.path.isfile(filename):
        print(f"Error: '{filename}' is not a readable file.")
        sys.exit(1)

    with open(filename, "rb") as f:
        plaintext = f.read()

    password = getpass.getpass("Master password: ")
    index = load_index()
    blob_name = blob_name_for(filename, index)
    blob = make_blob(plaintext, password)

    os.makedirs(VAULT_DIR, exist_ok=True)
    tmp_path = os.path.join(VAULT_DIR, blob_name + ".tmp")
    final_path = os.path.join(VAULT_DIR, blob_name)
    with open(tmp_path, "wb") as f:
        f.write(blob)
    os.replace(tmp_path, final_path)

    index[filename] = blob_name
    save_index(index)
    print(f"'{filename}' stored.")


def cmd_get(filename: str) -> None:
    index = load_index()
    if filename not in index:
        print(f"Error: '{filename}' not in vault.")
        sys.exit(1)

    blob_path = os.path.join(VAULT_DIR, index[filename])
    try:
        with open(blob_path, "rb") as f:
            blob = f.read()
    except OSError:
        print(f"Error: stored blob for '{filename}' is missing.")
        sys.exit(1)

    password = getpass.getpass("Master password: ")
    try:
        plaintext = open_blob(blob, password)
    except VaultError as exc:
        print(f"Error: {exc}.")
        sys.exit(1)

    with open(filename, "wb") as f:
        f.write(plaintext)
    print(f"'{filename}' recovered.")


def cmd_list() -> None:
    index = load_index()
    if not index:
        print("Vault is empty.")
        return
    for name in sorted(index):
        print(name)


def usage() -> None:
    print("Usage: python vault.py add <file> | get <file> | list")


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        usage()
        sys.exit(1)

    cmd = argv[1]
    if cmd == "add" and len(argv) == 3:
        cmd_add(argv[2])
    elif cmd == "get" and len(argv) == 3:
        cmd_get(argv[2])
    elif cmd == "list" and len(argv) == 2:
        cmd_list()
    else:
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
