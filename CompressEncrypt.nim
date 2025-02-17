import nimcrypto
import nimcrypto/sysrand
import base64
#import zippy
import zstd/compress
import zstd/decompress

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

func fromByteSeq*(data: seq[byte]): string {.inline.} =
  ## Converts a byte sequence to the corresponding string.
  cast[string](data)

func toCharSeq*(data: seq[byte]): seq[char] {.inline.} =
  ## Converts a byte sequence to the corresponding character sequence.
  cast[seq[char]](data)

const testData = """
  Lorem ipsum dolor sit amet, consectetur adipiscing elit. 
  Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. 
  Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. 
  Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. 
  Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
"""

var
    data: seq[byte] = toByteSeq(testData)
    envkey: string = "advapi32.dll"
    ectx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte] #= [0x08, 0x3f, 0x88, 0xcc, 0x22, 0x82, 0x06, 0xc4, 0x7f, 0x87, 0xb0, 0x8f, 0x0c, 0xc1, 0x89, 0x51]
    encrypted = newSeq[byte](len(data))

# Create Random IV
discard randomBytes(addr iv[0], 16)

# Expand key to 32 bytes using SHA256 as the KDF
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

ectx.init(key, iv)

var toEnc = compress(data, level=3)
echo "COMPRESSED: ", len(toEnc)
echo toEnc

ectx.encrypt(toEnc, encrypted)
ectx.clear()

echo "ENCTEXT: ", base64.encode(encrypted)
echo "------------------------------------------------------------"
echo "KEY: ", base64.encode(expandedkey.data)
echo "IV: ", base64.encode(iv)