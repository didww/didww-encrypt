# DIDWW Encrypt

![npm](https://img.shields.io/npm/v/@didww/encrypt)

Encrypts files for DIDWW V3 API in browser.

## Install

npm install @didww/encrypt

## Encryption demo

https://didww.github.io/didww-encrypt/

## Usage

```js
const DidwwEncrypt = require('@didww/encrypt')

const encryptor = new DidwwEncrypt({
    environment: 'sandbox'
})

let fingerprint = null
encryptor.getFingerprint().then(res => fingerprint = res) // => instance of String with fingerprint of public keys

// smallest png in base64 for an example
const pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=='
const pngFile = new File([atob(pngBase64)], 'test.png', { type: 'image/png', lastModified: new Date() })

let encryptedContainer = encryptor.encryptFile(pngFile).then(encrypted => {
    encryptedContainer.toFile() // => instance of File
    encryptedContainer.toArrayBuffer() // => instance of ArrayBuffer
    encryptedContainer.toString() // => instance of String in base64 format
})
```

or just load `dist/browser.js` to page and use `window.DidwwEncrypt`.

## Algorithm

Pseudocode that explains algorithm:

```
# parameter file - user provided file.
# returns binary content of a file as string.
function file_binary_content(file) { ... }

# parameter str - string.
# returns base64 encoded string.
base64_encode(str) { ... }

# parameter size - integer number of bytes.
# returns array of random bytes.
generate_random_bytes(size) { ... }

# parameter size - AES algorithm size (128, 256, 512, ...).
# parameter mode - AES algorighm mode (ECB, CBC, CFP, ...).
# parameter key - AES key of appropriate size (8 times smaller than size).
# parameter iv - AES iv of appropriate size (16 times smaller than size).
# parameter data - string that we want to encrypt.
# returns encrypted binary string.
# https://tools.ietf.org/html/rfc3602
encrypt_aes(size, mode, key, iv, data) { ... }

# parameter bytes - array of bytes.
# returns converted bytes array to hex string, each byte represents by 2 chars.
bytes_to_hex(bytes) { ... }

# parameter digest - digest mode used for OAEP padding (SHA128, SHA256, SHA512, ...).
# parameter label - label string used for OAEP padding.
# parameter data - string that we want to encrypt.
# returns encrypted binary string by RSA algorithm with OAEP padding.
# https://tools.ietf.org/html/rfc8017
encrypt_rsa_oeap(digest, label, public_key, data) { ... }

function encrypt (file, public_keys) {
  binary = file_binary_content(file)
  binary_base64 = base64_encode(binary)
  aes_key = generate_random_bytes(32)
  aes_iv = generate_random_bytes(16)
  encrypted_aes = encrypt_aes(256, 'CBC', aes_key, aes_iv, binary_base64)
  aes_key_hex = bytes_to_hex(aes_key)
  aes_iv_hex = bytes_to_hex(aes_iv)
  aes_credentials = "#{aes_key_hex}:::#{aes_iv_hex}"
  encrypted_rsa_a = encrypt_rsa_oeap('SHA256', '', public_keys[0], aes_credentials)
  encrypted_rsa_b = encrypt_rsa_oeap('SHA256', '', public_keys[1], aes_credentials)
  encrypted_rsa_a_base64 = base64_encode(encrypted_rsa_a)
  encrypted_rsa_b_base64 = base64_encode(encrypted_rsa_b)
  return "#{encrypted_rsa_a_base64}:::#{encrypted_rsa_b_base64}:::#{encrypted_aes}"
}
```

## Fingerprint generation
pseudocode
```
# parameter pem - RSA public key in pem format.
# returns RSA public key as bynary string (remove header/footer and decode from base64).
function pubkey_pem_to_bin(pem) { ... }

# parameter algo - string algorithm name (SHA1, SHA2, MD5, ...).
# parameter data - string content for digest.
# returns digest string for data.
function digest(algo, data) { ... }
      
function fingerprint (public_keys) {
  pubkey_bin_0 = pubkey_pem_to_bin(public_keys[0])
  pubkey_bin_1 = pubkey_pem_to_bin(public_keys[1])
  digest_0 = digest('SHA1', pubkey_bin_0)
  digest_1 = digest('SHA1', pubkey_bin_1)
  return "#{digest_0}:::#{digest_1}"
}
```
