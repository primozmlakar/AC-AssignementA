# Assignment A - Write-up Questions

## (a) Justify every cryptographic parameter you chose in `vault.py`: symmetric cipher and mode, key length, KDF and iteration count, MAC construction, and blob layout. For the iteration count in particular, explain the tradeoff between security and performance.

I used **AES-256-CBC** for encryption. AES is standard, and CBC is acceptable here because every file has a fresh 16-byte random IV and the ciphertext is authenticated before decryption.

I derive **64 bytes** with **PBKDF2-HMAC-SHA256**:

- the first 32 bytes are the AES-256 encryption key;
- the second 32 bytes are the HMAC-SHA256 key.

Each blob stores a fresh **16-byte random salt**, so the same password produces different key material for every file.

I chose **600,000 PBKDF2 iterations** as a practical classroom setting: it noticeably slows offline guessing while remaining usable for a command-line vault. The security/performance tradeoff is that increasing the count improves resistance to password cracking, but also makes every `add` and `get` operation slower for legitimate users.

The blob layout is:

```text
magic value || version || iteration count || salt || IV || ciphertext || HMAC tag
```

The 32-byte HMAC tag is computed over all previous fields.

## (b) Why must separate keys be used for encryption and authentication? What can go wrong when a single key serves both roles?

Separate keys are required because encryption and authentication have different security goals and assumptions.

Reusing one key can create cross-protocol interactions where information leaked or manipulated through one primitive affects the other. Key separation means that even if the encryption mode and MAC construction have different internal structure, using one primitive does not give an attacker a handle on the other.

## (c) Why is the authentication tag computed over the ciphertext rather than the plaintext, and why must it cover the salt and IV as well?

The tag is computed over the ciphertext, not the plaintext, so `vault.py` follows **encrypt-then-MAC**: it verifies authenticity before any decryption or unpadding occurs.

This prevents the program from acting as a padding oracle or otherwise exposing differences between decryption failures and authentication failures.

The tag also covers the salt and IV because changing either would change the derived keys or the first plaintext block. Unauthenticated metadata would let an attacker tamper with how valid ciphertext is interpreted.

## (d) What would an attacker be able to do if the salt were stored as a fixed constant rather than generated fresh per file?

A fixed salt would make the same password produce the same derived keys every time.

That lets attackers precompute password guesses for the fixed salt and reuse the work across all protected files. It also means two files encrypted under the same password do not get independent key material, so compromise or analysis of one target helps against the others.

## (e) Look up Argon2 (RFC 9106), the winner of the 2015 Password Hashing Competition. What does memory-hardness mean, and why does it make Argon2 more resistant to GPU-based attacks than PBKDF2? If you were designing vault.py today for production use, what would you change and why?

Argon2 is a memory-hard password hashing/KDF design standardized in **RFC 9106** after winning the **2015 Password Hashing Competition**.

Memory-hardness means the computation intentionally requires a large amount of RAM, not just many hash iterations. GPUs and ASICs are good at running many PBKDF2 guesses in parallel, but large per-guess memory requirements reduce that parallelism and increase hardware cost.

For a production vault today, I would use **Argon2id** with calibrated memory, time, and parallelism parameters instead of PBKDF2, while keeping encrypt-then-MAC or preferably using a misuse-resistant authenticated-encryption construction where suitable.
