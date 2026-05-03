import os, sys, json, hmac, hashlib, getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

VAULT_DIR  = ".vault_broken"
INDEX_FILE = os.path.join(VAULT_DIR, "index.json")

SALT               = b'appliedcrypto123'   # 16 bytes
IV_LEN             = 16
TAG_LEN            = 32
PBKDF2_ITERATIONS  = 1000

def derive_keys(password: str):
    key_material = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), SALT, PBKDF2_ITERATIONS, dklen=32)
    return key_material[:16], key_material[16:]

def load_index():
    if not os.path.exists(INDEX_FILE):
        return {}
    with open(INDEX_FILE) as f:
        return json.load(f)

def save_index(index):
    os.makedirs(VAULT_DIR, exist_ok=True)
    with open(INDEX_FILE, 'w') as f:
        json.dump(index, f)

def cmd_add(filename):
    with open(filename, 'rb') as f:
        plaintext = f.read()
    password = getpass.getpass("Master password: ")
    k_enc, k_mac = derive_keys(password)
    iv = os.urandom(IV_LEN)
    mac = hmac.new(k_mac, plaintext, hashlib.sha256).digest()
    cipher = AES.new(k_enc, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext + mac, AES.block_size))
    blob = iv + ciphertext
    blob_name = filename.replace(os.sep, '_') + '.bin'
    os.makedirs(VAULT_DIR, exist_ok=True)
    with open(os.path.join(VAULT_DIR, blob_name), 'wb') as f:
        f.write(blob)
    index = load_index()
    index[filename] = blob_name
    save_index(index)
    print(f"'{filename}' stored.")

def cmd_get(filename):
    index = load_index()
    if filename not in index:
        print(f"Error: '{filename}' not in vault.")
        sys.exit(1)
    with open(os.path.join(VAULT_DIR, index[filename]), 'rb') as f:
        blob = f.read()
    password = getpass.getpass("Master password: ")
    k_enc, k_mac = derive_keys(password)
    iv         = blob[:IV_LEN]
    ciphertext = blob[IV_LEN:]
    cipher = AES.new(k_enc, AES.MODE_CBC, iv)
    raw = unpad(cipher.decrypt(ciphertext), AES.block_size)
    plaintext, stored_mac = raw[:-TAG_LEN], raw[-TAG_LEN:]
    computed_mac = hmac.new(k_mac, plaintext, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, computed_mac):
        print("Error: wrong password or corrupted file.")
        sys.exit(1)
    with open(filename, 'wb') as f:
        f.write(plaintext)
    print(f"'{filename}' recovered.")

def cmd_list():
    index = load_index()
    if not index:
        print("Vault is empty.")
        return
    for name in sorted(index):
        print(f"  {name}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python vault_broken.py add <file> | get <file> | list")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'add':   cmd_add(sys.argv[2])
    elif cmd == 'get': cmd_get(sys.argv[2])
    elif cmd == 'list': cmd_list()