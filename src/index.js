const {
    SEPARATOR,
    FINGERPRINT_ALGO,
    SYM_ALGO,
    ASYM_ALGO,
    URLS
} = require('./constants')

function DidwwEncryptedFile (content) {
    this.toString = () => content
    this.toFile = (name) => buildFile(content, name || 'file.enc', 'text/plain')
    this.toArrayBuffer = () => stringToArrayBuffer(content)
}

function logError(message) {
    if (console && console.error) console.error(message)
}

function fetchPublicKeys(url) {
    return fetch(url)
        .then(response => response.json())
        .then(
            payload => payload.data.map(res => res.attributes.key)
        )
}

function cryptoFingerprint (text, digestAlgo) {
    var textBuff = stringToArrayBuffer(text);
    var sha1Func = crypto.subtle.digest.bind(crypto.subtle, digestAlgo);
    return sha1Func(textBuff)
        .then(digestBuff => arrayBufferToHexString(digestBuff))
}

function calculateFingerprint(pemPublicKeys) {
    let publicKeysBase64 = pemPublicKeys.map(pemPubKey => PemToBase64Key(pemPubKey))
    let fingerprints = []
    return cryptoFingerprint(atob(publicKeysBase64[0]), FINGERPRINT_ALGO)
        .then(result => fingerprints.push(result))
        .then(_ => cryptoFingerprint(atob(publicKeysBase64[1]), FINGERPRINT_ALGO))
        .then(result => fingerprints.push(result))
        .then(_ => fingerprints.join(SEPARATOR))
}

function stringToArrayBuffer(str) {
    let buf = new ArrayBuffer(str.length)
    let bufView = new Uint8Array(buf)
    for (let i = 0; i < str.length; i++) {
        bufView[i] = str.charCodeAt(i)
    }
    return buf
}

function hexStringToArrayBuffer (hexString) {
    let intArray = hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    return new Uint8Array(intArray).buffer
}

function arrayBufferToString (buf) {
    let bytes = new Uint8Array(buf)
    return bytes.reduce((str, byte) => str + String.fromCharCode(byte), "")
}

function arrayBufferToHexString (buf) {
    let bytes = new Uint8Array(buf)
    return bytes.reduce((hexString, byte) => {
        let byteString = byte.toString(16)
        if (byteString.length === 1) {
            byteString = '0' + byteString
        }
        return hexString + byteString
    }, "");
}

const buildFile = (content, name, type) => {
    // Edge browser does not support File
    if (window && window.navigator && window.navigator.msSaveBlob) {
        let file = new Blob([content], {type: type});
        file.lastModifiedDate = new Date();
        file.name = name;
        return file;
    }

    return new File([content], name, {type: type, lastModified: new Date()})
}

function readFileContent (file) {
    return new Promise((resolve, reject) => {
        let reader = new FileReader()
        reader.onload = () => resolve(reader.result)
        reader.onerror = () => reject(reader.error)
        reader.readAsDataURL(file)
    })
}

function generateKey () {
    return crypto.subtle.generateKey(
        SYM_ALGO,
        true,
        ["encrypt", "decrypt"]
    ).then(cryptoKey => {
        return crypto.subtle.exportKey("raw", cryptoKey)
            .then(keyBuffer => arrayBufferToHexString(keyBuffer))
    })
}

function encryptAES (key, content) {
    let keyBuffer = hexStringToArrayBuffer(key)
    let ivBufView = crypto.getRandomValues(new Uint8Array(16))
    let salt = '0'.repeat(16)

    return crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: SYM_ALGO.name },
        false,
        ["encrypt", "decrypt"]
    ).then(cryptoKey => {
        return crypto.subtle.encrypt(
            { name: SYM_ALGO.name, iv: ivBufView },
            cryptoKey,
            stringToArrayBuffer(content)
        ).then(encryptedBuffer => {
            // add first 16 bytes salt for backward compatibility old encrypted data.
            let encryptedContent = btoa(salt + arrayBufferToString(encryptedBuffer))
            let aesKey = [key, arrayBufferToHexString(ivBufView.buffer)].join(SEPARATOR)
            return { key: aesKey, content: encryptedContent }
        })
    })
}

function PemToBase64Key (pemPubKey) {
    // pemPubKey should look like this
    // "-----BEGIN PUBLIC KEY-----\n<pubKeyBase64>\n-----END PUBLIC KEY-----\n"
    if (pemPubKey[pemPubKey.length - 1] !== "\n") pemPubKey = pemPubKey + "\n"
    return pemPubKey.split("\n").slice(1, -2).join("")
}

function encryptRSA(pemPubKey, content) {
    let pubKeyBase64 = PemToBase64Key(pemPubKey)

    return crypto.subtle.importKey(
        "spki",
        stringToArrayBuffer(atob(pubKeyBase64)),
        ASYM_ALGO,
        false,
        ["encrypt"]
    ).then(function (cryptoKey) {
        return crypto.subtle.encrypt(
            {
                name: ASYM_ALGO.name,
                hash: ASYM_ALGO.hash
            },
            cryptoKey,
            stringToArrayBuffer(content)
        ).then(function (encryptedBuffer) {
            return btoa(arrayBufferToString(encryptedBuffer))
        }).catch(function (error) {
            logError("Failed to encrypt with RSA pubKey", error)
            return null
        })
    }).catch(function (error) {
        logError("Failed to import RSA pubKey", error)
        return null
    })
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
        if (!testPublicKeys || !testPublicKeys[0] ||  !testPublicKeys[1]) {
            throw 'pass publicKeys as an array of 2 public keys'
        }
    } else if (!publicKeysUrl) {
        throw 'pass valid environment or url'
    }

    this.getPublicKeys = () => {
        if (testPublicKeys) return new Promise(resolve => resolve(testPublicKeys))
        if (publicKeys) return new Promise(resolve => resolve(publicKeys))

        return fetchPublicKeys(publicKeysUrl)
            .then(result => {
                publicKeys = result
                return publicKeys
            })
    }
    this.getFingerprint = () => {
        if (fingerprint) return new Promise(resolve => resolve(fingerprint))

        return this.getPublicKeys()
            .then(keys => calculateFingerprint(keys))
            .then(result => {
                fingerprint = result
                return fingerprint
            })
    }
    this.clearCache = () => {
        publicKeys = null
        fingerprint = null
    }
    this.encryptContent = fileContent => {
        let asymKeys = null
        let symKey = null
        let symEncryptedContent = null
        let symEncryptedKey = null // { content, key }
        let encryptedParts = []

        return this.getPublicKeys().then(result => asymKeys = result)
            .then(
                _ => generateKey().then(result => symKey = result)
            )
            .then(
                _ => encryptAES(symKey, fileContent).then(result => {
                    symEncryptedContent = result.content
                    symEncryptedKey = result.key
                })
            )
            .then(
                _ => encryptRSA(asymKeys[0], symEncryptedKey).then(result => encryptedParts.push(result))
            )
            .then(
                _ => encryptRSA(asymKeys[1], symEncryptedKey).then(result => encryptedParts.push(result))
            )
            .then(_ => {
                return new DidwwEncryptedFile(
                    encryptedParts.concat(symEncryptedContent).join(SEPARATOR)
                )
            })
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
