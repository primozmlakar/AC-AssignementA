# Broken Vault Analysis

## Flaw 1: Fixed salt

Line 7 sets:

```python
SALT = b'appliedcrypto123'
```

Line 15 passes that same `SALT` into PBKDF2 for every file:

```python
key_material = hashlib.pbkdf2_hmac(
    'sha256', password.encode(), SALT, PBKDF2_ITERATIONS, dklen=32)
```

This enables reusable precomputation and makes identical passwords produce identical encryption/MAC keys across files.

## Flaw 2: Low PBKDF2 iteration count

Line 11 sets:

```python
PBKDF2_ITERATIONS = 1000
```

Line 15 uses that value in PBKDF2.

That is too low by modern standards and makes offline dictionary attacks much faster after an attacker steals vault blobs.

## Flaw 3: MAC-then-encrypt

Line 36 computes the MAC over plaintext:

```python
mac = hmac.new(k_mac, plaintext, hashlib.sha256).digest()
```

Line 38 encrypts `plaintext + mac`:

```python
ciphertext = cipher.encrypt(pad(plaintext + mac, AES.block_size))
```

On recovery, line 61 decrypts and unpads before line 64 verifies the MAC:

```python
raw = unpad(cipher.decrypt(ciphertext), AES.block_size)
```

```python
if not hmac.compare_digest(stored_mac, computed_mac):
```

This creates attack surface because malformed ciphertext is processed before authentication, potentially exposing padding-oracle or error-behaviour differences.

`vault.py` avoids this by authenticating the header, salt, IV, and ciphertext first, and only decrypting if `hmac.compare_digest` succeeds.

# Tamper Demonstration

After adding a file, I would corrupt one byte of its blob, for example by flipping byte 40 in the `.vault/*.bin` file.

Example:

```bash
python -c "d=open('.vault/file.bin','rb').read(); open('.vault/file.bin','wb').write(d[:40]+bytes([d[40]^0xFF])+d[41:])"
```

Then I would run:

```bash
python vault.py get <filename>
```

The program prints:

```text
Error: wrong password or corrupted file.
```

This happens because the HMAC verification fails before decryption.
