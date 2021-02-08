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
    production: 'https://my.didww.com/public_keys',
    sandbox: 'https://my-sandbox.didww.com/public_keys',
    staging: 'https://my-staging.didww.com/public_keys',
    test: null,
    local: ''
}

module.exports = {
    SEPARATOR,
    FINGERPRINT_ALGO,
    SYM_ALGO,
    ASYM_ALGO,
    URLS
}
