# DIDWW Encrypt

![npm](https://img.shields.io/npm/v/@didww/encrypt)

Encrypts files for DIDWW V3 API in browser.

## Install

npm install @didww/encrypt

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
