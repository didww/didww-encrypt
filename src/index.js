const {
    SEPARATOR,
    FINGERPRINT_ALGO,
    SYM_ALGO,
    ASYM_ALGO,
    URLS
} = require('./constants')

function DidwwEncryptedFile(content) {
    this.toString = () => content
    this.toFile = (name) => buildFile(content, name || 'file.enc', 'text/plain')
    this.toArrayBuffer = () => stringToArrayBuffer(content)
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
    const publicKeysBase64 = pemPublicKeys.map(pemPubKey => PemToBase64Key(pemPubKey))
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

function hexStringToArrayBuffer(hexString) {
    let intArray = hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    return new Uint8Array(intArray).buffer
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

function buildFile(content, name, type) {
    // Edge browser does not support File
    if (window && window.navigator && window.navigator.msSaveBlob) {
        let file = new Blob([content], { type: type });
        file.lastModifiedDate = new Date();
        file.name = name;
        return file;
    }

    return new File([content], name, { type: type, lastModified: new Date() })
}

function readFileContent(file) {
    return new Promise((resolve, reject) => {
        let reader = new FileReader()
        reader.onload = () => resolve(reader.result)
        reader.onerror = () => reject(reader.error)
        reader.readAsDataURL(file)
    })
}

async function generateKey() {
    const cryptoKey = await crypto.subtle.generateKey(
        SYM_ALGO,
        true,
        ["encrypt", "decrypt"]
    )
    const keyBuffer = await crypto.subtle.exportKey("raw", cryptoKey)
    return arrayBufferToHexString(keyBuffer)
}

async function encryptAES(key, content) {
    const keyBuffer = hexStringToArrayBuffer(key)
    const ivBufView = crypto.getRandomValues(new Uint8Array(16))
    const salt = '0'.repeat(16)
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
            { name: SYM_ALGO.name, iv: ivBufView },
            cryptoKey,
            stringToArrayBuffer(content)
        )
        const encryptedContent = btoa(salt + arrayBufferToString(encryptedBuffer))
        const aesKey = [key, arrayBufferToHexString(ivBufView.buffer)].join(SEPARATOR)
        return { key: aesKey, content: encryptedContent }
    } catch (e) {
        logError('Exception during encrypt AES', e)
        return null
    }
}

function PemToBase64Key(pemPubKey) {
    // pemPubKey should look like this
    // "-----BEGIN PUBLIC KEY-----\n<pubKeyBase64>\n-----END PUBLIC KEY-----\n"
    if (pemPubKey[pemPubKey.length - 1] !== "\n") pemPubKey = pemPubKey + "\n"
    return pemPubKey.split("\n").slice(1, -2).join("")
}

async function encryptRSA(pemPubKey, content) {
    const pubKeyBase64 = PemToBase64Key(pemPubKey)
    let cryptoKey = null;

    try {
        cryptoKey = await crypto.subtle.importKey(
            "spki",
            stringToArrayBuffer(atob(pubKeyBase64)),
            ASYM_ALGO,
            false,
            ["encrypt"]
        )
    } catch (e) {
        logError("Failed to import RSA pubKey", e)
        return null
    }

    try {
        const encryptedBuffer = await crypto.subtle.encrypt(
            {
                name: ASYM_ALGO.name,
                hash: ASYM_ALGO.hash
            },
            cryptoKey,
            stringToArrayBuffer(content)
        )
        return btoa(arrayBufferToString(encryptedBuffer))
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
    this.encryptContent = async fileContent => {
        const RsaKeys = await this.getPublicKeys()
        const aesKey = await generateKey()
        const encryptedAes = await encryptAES(aesKey, fileContent)
        const encryptedParts = [
            await encryptRSA(RsaKeys[0], encryptedAes.key),
            await encryptRSA(RsaKeys[1], encryptedAes.key)
        ]
        return new DidwwEncryptedFile(
            encryptedParts.concat(encryptedAes.content).join(SEPARATOR)
        )
    }
    this.encryptFile = file => {
        return readFileContent(file).then(this.encryptContent)
    }
    this.encryptArrayBuffer = buffer => {
        let binary = arrayBufferToString(buffer)
        return this.encryptContent(binary)
    }
}

DidwwEncrypt['DidwwEncryptedFile'] = DidwwEncryptedFile
DidwwEncrypt['SYM_ALGO'] = SYM_ALGO
DidwwEncrypt['ASYM_ALGO'] = ASYM_ALGO

// export default DidwwEncrypt
module.exports = DidwwEncrypt
