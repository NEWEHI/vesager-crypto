# vesager-crypto

Open source cryptography layer of [Vesager](https://vesager.com).

This module contains the client-side cryptographic operations of Vesager.
The encryption key never leaves the browser — all encryption and decryption
happens here, on the client, before any data reaches the server.

## Methods

- AES-256-GCM (encryption)
- PBKDF2 + HKDF-SHA256 (password key derivation)
- Web Crypto API (native browser cryptography)

## License

MIT
