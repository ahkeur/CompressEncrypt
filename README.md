# CompressEncrypt

# Encryption and Compression Scripts

This project contains two scripts: `CompressEncrypt.nim` and `DecryptDecompress.py`. These scripts demonstrate how to compress and encrypt data, and then decrypt and decompress it.

## CompressEncrypt.nim

This Nim script performs the following tasks:
1. Converts a string to a byte sequence.
2. Compresses the byte sequence using Zstandard (zstd) compression.
3. Encrypts the compressed data using AES-256 in CTR mode.
4. Outputs the encrypted data, the key, and the IV in base64 encoding.

### Key Components:
- **Compression**: Uses the `zstd/compress` module to compress the data.
- **Encryption**: Uses the `nimcrypto` library to perform AES-256 encryption in CTR mode.
- **Key Derivation**: Uses SHA-256 to derive a 32-byte key from a given string.

## DecryptDecompress.py

This Python script performs the following tasks:
1. Decodes the base64-encoded ciphertext, key, and IV.
2. Decrypts the ciphertext using AES-256 in CTR mode.
3. Decompresses the decrypted data using Zstandard (zstd) decompression.
4. Prints the decompressed data.

### Key Components:
- **Decryption**: Uses the `pycryptodome` library to perform AES-256 decryption in CTR mode.
- **Decompression**: Uses the `zstandard` library to decompress the data.

## Usage

1. Run `CompressEncrypt.nim` to compress and encrypt your data. The script will output the encrypted data, key, and IV.
2. Use the output from the Nim script as input for `DecryptDecompress.py` to decrypt and decompress the data.

Ensure you have the necessary dependencies installed for both scripts:
- Nim dependencies: `nimcrypto`, `zstd`
- Python dependencies: `pycryptodome`, `zstandard`

## Credits

- https://github.com/wltsmrz/nim_zstd
- https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/encrypt_decrypt_bin.nim
- https://github.com/indygreg/python-zstandard