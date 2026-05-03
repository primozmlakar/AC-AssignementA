# AC - Assignement A

In this assignment you will design and build a command-line file vault that protects stored files with password-based authenticated encryption. The cryptographic design is yours to make — you must choose your algorithms, parameters, and construction, and justify every decision. You will then analyse a deliberately broken vault implementation, identify its flaws, and demonstrate at least one of them in code.

The construction you build — PBKDF2 key derivation feeding a symmetric cipher with a separate authentication tag — is the same pattern standardised in **PKCS#5 (RFC 8018)**, used in encrypted PEM private keys, PKCS#12 keystores, and encrypted ZIP archives. The flaws in `vault_broken.py` are not hypothetical: the 2022 LastPass breach exposed encrypted user vaults to offline attack, and their practical crackability depended directly on how many PBKDF2 iterations each account had been configured with.
