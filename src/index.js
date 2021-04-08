const {
    SEPARATOR,
    FINGERPRINT_ALGO,
    SYM_ALGO,
    ASYM_ALGO,
    URLS
} = require('./constants')

function DidwwEncryptedFile(buffer) {
    this.toString = () => arrayBufferToString(buffer)
    this.toBase64String = () => btoa(arrayBufferToString(buffer))
    this.toFile = (name) => buildFile(buffer, name || 'file.enc', 'text/plain')
    this.toArrayBuffer = () => buffer
}

function logError(message) {
    if (console && console.error) console.error(message)
}

async function fetchPublicKeys(url) {
    const response = await fetch(url)
    const payload = await response.json()
    return payload.data.map(res => res.attributes.key)
}

function cryptoFingerprint(text, digestAlgo) {
    const textBuff = stringToArrayBuffer(text);
    const sha1Func = crypto.subtle.digest.bind(crypto.subtle, digestAlgo);
    return sha1Func(textBuff)
        .then(digestBuff => arrayBufferToHexString(digestBuff))
}

async function calculateFingerprint(pemPublicKeys) {
    const publicKeysBase64 = pemPublicKeys.map(pemPubKey => pemToBase64Key(pemPubKey))
    return [
        await cryptoFingerprint(atob(publicKeysBase64[0]), FINGERPRINT_ALGO),
        await cryptoFingerprint(atob(publicKeysBase64[1]), FINGERPRINT_ALGO),
    ].join(SEPARATOR)
}

function stringToArrayBuffer(str) {
    let buf = new ArrayBuffer(str.length)
    let bufView = new Uint8Array(buf)
    for (let i = 0; i < str.length; i++) {
        bufView[i] = str.charCodeAt(i)
    }
    return buf
}

function concatArrayBuffers(buffers) {
    if (buffers.length === 1) return buffers[0];

    let size = 0
    buffers.forEach(b => size += b.byteLength)
    const result = new Uint8Array(size)
    buffers.forEach( (buffer, index) => {
        const offset = index === 0 ? 0 : buffers[index - 1].byteLength
        result.set(new Uint8Array(buffer), offset)
    })
    return result.buffer
}

function arrayBufferToString(buf) {
    let bytes = new Uint8Array(buf)
    return bytes.reduce((str, byte) => str + String.fromCharCode(byte), "")
}

function arrayBufferToHexString(buf) {
    let bytes = new Uint8Array(buf)
    return bytes.reduce((hexString, byte) => {
        let byteString = byte.toString(16)
        if (byteString.length === 1) {
            byteString = '0' + byteString
        }
        return hexString + byteString
    }, "");
}

function buildFile(buffer, name, type) {
    // Edge browser does not support File
    if (window && window.navigator && window.navigator.msSaveBlob) {
        let file = new Blob([buffer], { type: type });
        file.lastModifiedDate = new Date();
        file.name = name;
        return file;
    }

    return new File([buffer], name, { type: type, lastModified: new Date() })
}

function readFileContent(file) {
    return new Promise((resolve, reject) => {
        let reader = new FileReader()
        reader.onload = () => resolve(reader.result)
        reader.onerror = () => reject(reader.error)
        reader.readAsArrayBuffer(file)
    })
}

function pemToBase64Key(pubKeyPem) {
    // pemPubKey should look like this
    // "-----BEGIN PUBLIC KEY-----\n<pubKeyBase64>\n-----END PUBLIC KEY-----\n"
    if (pubKeyPem[pubKeyPem.length - 1] !== "\n") pubKeyPem = pubKeyPem + "\n"
    return pubKeyPem.split("\n").slice(1, -2).join("")
}

async function generateKey() {
    const cryptoKey = await crypto.subtle.generateKey(
        SYM_ALGO,
        true,
        ["encrypt", "decrypt"]
    )
    return await crypto.subtle.exportKey("raw", cryptoKey)
}

function generateRandomArrayBuffer(size) {
    return crypto.getRandomValues(new Uint8Array(size)).buffer
}

async function encryptAES(dataBuffer) {
    const keyBuffer = await generateKey()
    const ivBuffer = generateRandomArrayBuffer(16)
    let cryptoKey = null;

    try {
        cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: SYM_ALGO.name },
            false,
            ["encrypt", "decrypt"]
        )
    } catch (e) {
        logError('Exception during import AES key', e)
        return null
    }

    try {
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: SYM_ALGO.name, iv: ivBuffer },
            cryptoKey,
            dataBuffer
        )
        return { key: keyBuffer, iv: ivBuffer, data: encryptedBuffer }
    } catch (e) {
        logError('Exception during encrypt AES', e)
        return null
    }
}

async function encryptRSA(pubKeyPem, dataBuffer) {
    const pubKeyBuffer = stringToArrayBuffer(atob(pemToBase64Key(pubKeyPem)))
    let cryptoKey = null;

    try {
        cryptoKey = await crypto.subtle.importKey(
            "spki",
            pubKeyBuffer,
            ASYM_ALGO,
            false,
            ["encrypt"]
        )
    } catch (e) {
        logError("Failed to import RSA pubKey", e)
        return null
    }

    try {
        return await crypto.subtle.encrypt(
            {
                name: ASYM_ALGO.name,
                hash: ASYM_ALGO.hash
            },
            cryptoKey,
            dataBuffer
        )
    } catch (e) {
        logError("Failed to encrypt RSA", e)
        return null
    }
}

function DidwwEncrypt(options) {
    if (!options) options = {}
    let environment = options.environment || 'sandbox'
    let publicKeysUrl = options.url || URLS[environment]
    let publicKeys = null
    let testPublicKeys = null
    let fingerprint = null
    if (environment === 'test') {
        testPublicKeys = options.publicKeys
        if (!testPublicKeys || !testPublicKeys[0] || !testPublicKeys[1]) {
            throw 'pass publicKeys as an array of 2 public keys'
        }
    } else if (!publicKeysUrl) {
        throw 'pass valid environment or url'
    }

    this.getPublicKeys = async () => {
        if (testPublicKeys) return testPublicKeys
        if (publicKeys) return publicKeys

        publicKeys = await fetchPublicKeys(publicKeysUrl)
        return publicKeys
    }
    this.getFingerprint = async () => {
        if (fingerprint) return fingerprint

        const keys = await this.getPublicKeys()
        fingerprint = await calculateFingerprint(keys)
        return fingerprint
    }
    this.clearCache = () => {
        publicKeys = null
        fingerprint = null
    }
    this.encrypt = async buffer => {
        const RsaKeys = await this.getPublicKeys()
        const encryptedAes = await encryptAES(buffer)
        const AesKeyIvBuffer = concatArrayBuffers([encryptedAes.key, encryptedAes.iv])
        const encryptedAesKeyIvBufferA = await encryptRSA(RsaKeys[0], AesKeyIvBuffer)
        const encryptedAesKeyIvBufferB = await encryptRSA(RsaKeys[1], AesKeyIvBuffer)
        const encryptedBuffer = concatArrayBuffers([
            encryptedAesKeyIvBufferA,
            encryptedAesKeyIvBufferB,
            encryptedAes.data
        ])
        return new DidwwEncryptedFile(encryptedBuffer)
    }
    this.encryptContent = async binaryContent => {
        return this.encrypt(stringToArrayBuffer(binaryContent))
    }
    this.encryptFile = file => {
        return readFileContent(file).then(buffer => this.encrypt(buffer))
    }
}

DidwwEncrypt['DidwwEncryptedFile'] = DidwwEncryptedFile
DidwwEncrypt['SYM_ALGO'] = SYM_ALGO
DidwwEncrypt['ASYM_ALGO'] = ASYM_ALGO

// export default DidwwEncrypt
module.exports = DidwwEncrypt
