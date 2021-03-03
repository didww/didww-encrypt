const SEPARATOR = ":::"
const FINGERPRINT_ALGO = { name: "sha-1" }
const SYM_ALGO = { name: "AES-CBC", length: 256 }
const ASYM_ALGO = {
    name: "RSA-OAEP",
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: { name: "SHA-256" }
}
const URLS = {
    production: 'https://api.didww.com/v3/public_keys',
    sandbox: 'https://api-sandbox.didww.com/v3/public_keys'
}

module.exports = {
    SEPARATOR,
    FINGERPRINT_ALGO,
    SYM_ALGO,
    ASYM_ALGO,
    URLS
}
