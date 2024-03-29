import DidwwEncrypt from '@didww/encrypt'

const encryptor = new DidwwEncrypt({
    environment: 'sandbox'
})
// or you can pass your'e own public keys in PEM format with environment test
// const encryptor = new DidwwEncrypt({
//     environment: 'test',
//     // keys
//     public_keys:[
//         '',
//         ''
//     ]
// })

let fingerprint = null
encryptor.getFingerprint().then(res => fingerprint = res) // => instance of String with fingerprint of public keys

// smallest png in base64 for an example
let pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=='
let pngFile = new File([atob(pngBase64)], 'test.png', { type: 'image/png', lastModified: new Date() })

let encryptedContainer = encryptor.encryptFile(pngFile).then(encrypted => {
    encryptedContainer.toFile() // => instance of File
    encryptedContainer.toArrayBuffer() // => instance of ArrayBuffer
    encryptedContainer.toString() // => instance of String in base64 format
})
