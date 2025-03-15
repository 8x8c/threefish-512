# threefish-512


see /docs


Encryption and decryption using Threefish-512 in CTR mode.

Integrity verification via HMAC-SHA512.

Secure password-based key derivation using Argon2id.

# 1. Cryptographic Strength of Threefish-512
Threefish is a block cipher designed as part of the Skein hash function submission to the SHA-3 competition by Bruce Schneier, Niels Ferguson, and others.

Threefish-512 has a 512-bit key and a 128-bit tweak, and runs 72 rounds by design. Although it was not ultimately selected as the SHA-3 winner (Keccak was chosen), Threefish itself has no known practical cryptanalytic breaks and is generally considered secure.

Even with a secure cipher, key management remains critical. If an attacker obtains the key, they can decrypt the data.
