# threefish-512


see /docs


Encryption and decryption using Threefish-512 in CTR mode.

Integrity verification via HMAC-SHA512.

Secure password-based key derivation using Argon2id.

# 1. Cryptographic Strength of Threefish-512
Threefish is a block cipher designed as part of the Skein hash function submission to the SHA-3 competition by Bruce Schneier, Niels Ferguson, and others.

Threefish-512 has a 512-bit key and a 128-bit tweak, and runs 72 rounds by design. Although it was not ultimately selected as the SHA-3 winner (Keccak was chosen), Threefish itself has no known practical cryptanalytic breaks and is generally considered secure.

Even with a secure cipher, key management remains critical. If an attacker obtains the key, they can decrypt the data.

 # CTR Mode Considerations
This tool uses CTR-like mode with Threefish-512. CTR is a well-known mode that turns a block cipher into a stream cipher by:
Encrypting a zero block,
XORing the output with the plaintext,
Incrementing a counter for each block.
Uniqueness of Nonce/Counter: For CTR to remain secure, each block must see a unique nonce+counter combination. We generate a random 16-byte nonce at each encryption, and combine it with a per-block counter. This is standard practice. If a nonce were ever reused with the same key, an attacker could observe patterns in the XOR stream (it’s a known hazard of CTR mode). But as long as the nonce is truly random on each encryption and never reused with the same password-salt combination, the CTR approach is sound.
