#!/usr/bin/env python3
"""Requirement 5: demonstrate that vault_broken.py uses identical keys."""
from vault_broken import derive_keys

password = "correct horse battery staple"
file_a = "alpha.txt"
file_b = "beta.txt"

enc_a, mac_a = derive_keys(password)
enc_b, mac_b = derive_keys(password)

print(f"Filename A: {file_a}")
print(f"Encryption key A: {enc_a.hex()}")
print(f"MAC key A:        {mac_a.hex()}")
print()
print(f"Filename B: {file_b}")
print(f"Encryption key B: {enc_b.hex()}")
print(f"MAC key B:        {mac_b.hex()}")

assert enc_a == enc_b
assert mac_a == mac_b

# This is dangerous because a fixed global salt makes the password-derived keys
# identical for every file protected by the same password. Attackers can precompute
# guesses once and reuse the work across all files/users with that salt, and equal
# passwords always produce equal key material instead of independent per-file keys.
print("\nAssertion passed: both filenames produced identical derived keys.")
