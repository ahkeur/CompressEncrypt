from Crypto.Cipher import AES # type: ignore
from Crypto.Util import Counter # type: ignore
from base64 import b64decode
import hashlib
import zstandard as zstd # type: ignore

ciphertext = b64decode("") # Add the base64 encoded ciphertext here
key = b64decode("") # Add the base64 encoded key here
iv = b64decode("") # Add the base64 encoded IV here

# Create a counter object from the IV
ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))

# Create the AES cipher object in CTR mode
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

# Decrypt the ciphertext
decrypted_data = cipher.decrypt(ciphertext)

try:
    dctx = zstd.ZstdDecompressor()
    decompressed = dctx.decompress(decrypted_data)
    print(decompressed.decode())
except Exception as e:
    print(f"ZLIB decompression failed: {e}")