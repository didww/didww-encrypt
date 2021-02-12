// modules are defined as an array
// [ module function, map of requires ]
//
// map of requires is short require name -> numeric require
//
// anything defined in a previous bundle is accessed via the
// orig method which is the require for previous bundles
parcelRequire = (function (modules, cache, entry, globalName) {
  // Save the require from previous bundle to this closure if any
  var previousRequire = typeof parcelRequire === 'function' && parcelRequire;
  var nodeRequire = typeof require === 'function' && require;

  function newRequire(name, jumped) {
    if (!cache[name]) {
      if (!modules[name]) {
        // if we cannot find the module within our internal map or
        // cache jump to the current global require ie. the last bundle
        // that was added to the page.
        var currentRequire = typeof parcelRequire === 'function' && parcelRequire;
        if (!jumped && currentRequire) {
          return currentRequire(name, true);
        }

        // If there are other bundles on this page the require from the
        // previous one is saved to 'previousRequire'. Repeat this as
        // many times as there are bundles until the module is found or
        // we exhaust the require chain.
        if (previousRequire) {
          return previousRequire(name, true);
        }

        // Try the node require function if it exists.
        if (nodeRequire && typeof name === 'string') {
          return nodeRequire(name);
        }

        var err = new Error('Cannot find module \'' + name + '\'');
        err.code = 'MODULE_NOT_FOUND';
        throw err;
      }

      localRequire.resolve = resolve;
      localRequire.cache = {};

      var module = cache[name] = new newRequire.Module(name);

      modules[name][0].call(module.exports, localRequire, module, module.exports, this);
    }

    return cache[name].exports;

    function localRequire(x){
      return newRequire(localRequire.resolve(x));
    }

    function resolve(x){
      return modules[name][1][x] || x;
    }
  }

  function Module(moduleName) {
    this.id = moduleName;
    this.bundle = newRequire;
    this.exports = {};
  }

  newRequire.isParcelRequire = true;
  newRequire.Module = Module;
  newRequire.modules = modules;
  newRequire.cache = cache;
  newRequire.parent = previousRequire;
  newRequire.register = function (id, exports) {
    modules[id] = [function (require, module) {
      module.exports = exports;
    }, {}];
  };

  var error;
  for (var i = 0; i < entry.length; i++) {
    try {
      newRequire(entry[i]);
    } catch (e) {
      // Save first error but execute all entries
      if (!error) {
        error = e;
      }
    }
  }

  if (entry.length) {
    // Expose entry point to Node, AMD or browser globals
    // Based on https://github.com/ForbesLindesay/umd/blob/master/template.js
    var mainExports = newRequire(entry[entry.length - 1]);

    // CommonJS
    if (typeof exports === "object" && typeof module !== "undefined") {
      module.exports = mainExports;

    // RequireJS
    } else if (typeof define === "function" && define.amd) {
     define(function () {
       return mainExports;
     });

    // <script>
    } else if (globalName) {
      this[globalName] = mainExports;
    }
  }

  // Override the current require with this new one
  parcelRequire = newRequire;

  if (error) {
    // throw error from earlier, _after updating parcelRequire_
    throw error;
  }

  return newRequire;
})({"iJA9":[function(require,module,exports) {
var SEPARATOR = ":::";
var FINGERPRINT_ALGO = {
  name: "sha-1"
};
var SYM_ALGO = {
  name: "AES-CBC",
  length: 256
};
var ASYM_ALGO = {
  name: "RSA-OAEP",
  modulusLength: 4096,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: {
    name: "SHA-256"
  }
};
var URLS = {
  production: 'https://my.didww.com/public_keys',
  sandbox: 'https://my-sandbox.didww.com/public_keys',
  staging: 'https://my-staging.didww.com/public_keys',
  test: null,
  local: ''
};
module.exports = {
  SEPARATOR: SEPARATOR,
  FINGERPRINT_ALGO: FINGERPRINT_ALGO,
  SYM_ALGO: SYM_ALGO,
  ASYM_ALGO: ASYM_ALGO,
  URLS: URLS
};
},{}],"Focm":[function(require,module,exports) {
var _require = require('./constants'),
    SEPARATOR = _require.SEPARATOR,
    FINGERPRINT_ALGO = _require.FINGERPRINT_ALGO,
    SYM_ALGO = _require.SYM_ALGO,
    ASYM_ALGO = _require.ASYM_ALGO,
    URLS = _require.URLS;

function DidwwEncryptedFile(content) {
  this.toString = function () {
    return content;
  };

  this.toFile = function (name) {
    return buildFile(content, name || 'file.enc', 'text/plain');
  };

  this.toArrayBuffer = function () {
    return stringToArrayBuffer(content);
  };
}

function logError(message) {
  if (console && console.error) console.error(message);
}

function fetchPublicKeys(url) {
  return fetch(url).then(function (response) {
    return response.json();
  }).then(function (keys) {
    return [keys.key_a, keys.key_b];
  });
}

function cryptoFingerprint(text, digestAlgo) {
  var textBuff = stringToArrayBuffer(text);
  var sha1Func = crypto.subtle.digest.bind(crypto.subtle, digestAlgo);
  return sha1Func(textBuff).then(function (digestBuff) {
    return arrayBufferToHexString(digestBuff);
  });
}

function calculateFingerprint(pemPublicKeys) {
  var publicKeysBase64 = pemPublicKeys.map(function (pemPubKey) {
    return PemToBase64Key(pemPubKey);
  });
  var fingerprints = [];
  return cryptoFingerprint(atob(publicKeysBase64[0]), FINGERPRINT_ALGO).then(function (result) {
    return fingerprints.push(result);
  }).then(function (_) {
    return cryptoFingerprint(atob(publicKeysBase64[1]), FINGERPRINT_ALGO);
  }).then(function (result) {
    return fingerprints.push(result);
  }).then(function (_) {
    return fingerprints.join(SEPARATOR);
  });
}

function stringToArrayBuffer(str) {
  var buf = new ArrayBuffer(str.length);
  var bufView = new Uint8Array(buf);

  for (var i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }

  return buf;
}

function hexStringToArrayBuffer(hexString) {
  var intArray = hexString.match(/.{1,2}/g).map(function (byte) {
    return parseInt(byte, 16);
  });
  return new Uint8Array(intArray).buffer;
}

function arrayBufferToString(buf) {
  var bytes = new Uint8Array(buf);
  return bytes.reduce(function (str, byte) {
    return str + String.fromCharCode(byte);
  }, "");
}

function arrayBufferToHexString(buf) {
  var bytes = new Uint8Array(buf);
  return bytes.reduce(function (hexString, byte) {
    var byteString = byte.toString(16);

    if (byteString.length === 1) {
      byteString = '0' + byteString;
    }

    return hexString + byteString;
  }, "");
}

var buildFile = function buildFile(content, name, type) {
  // Edge browser does not support File
  if (window && window.navigator && window.navigator.msSaveBlob) {
    var file = new Blob([content], {
      type: type
    });
    file.lastModifiedDate = new Date();
    file.name = name;
    return file;
  }

  return new File([content], name, {
    type: type,
    lastModified: new Date()
  });
};

function readFileContent(file) {
  return new Promise(function (resolve, reject) {
    var reader = new FileReader();

    reader.onload = function () {
      return resolve(reader.result);
    };

    reader.onerror = function () {
      return reject(reader.error);
    };

    reader.readAsDataURL(file);
  });
}

function generateKey() {
  return crypto.subtle.generateKey(SYM_ALGO, true, ["encrypt", "decrypt"]).then(function (cryptoKey) {
    return crypto.subtle.exportKey("raw", cryptoKey).then(function (keyBuffer) {
      return arrayBufferToHexString(keyBuffer);
    });
  });
}

function encryptAES(key, content) {
  var keyBuffer = hexStringToArrayBuffer(key);
  var ivBufView = crypto.getRandomValues(new Uint8Array(16));
  var salt = '0'.repeat(16);
  return crypto.subtle.importKey("raw", keyBuffer, {
    name: SYM_ALGO.name
  }, false, ["encrypt", "decrypt"]).then(function (cryptoKey) {
    return crypto.subtle.encrypt({
      name: SYM_ALGO.name,
      iv: ivBufView
    }, cryptoKey, stringToArrayBuffer(content)).then(function (encryptedBuffer) {
      // add first 16 bytes salt for backward compatibility old encrypted data.
      var encryptedContent = btoa(salt + arrayBufferToString(encryptedBuffer));
      var aesKey = [key, arrayBufferToHexString(ivBufView.buffer)].join(SEPARATOR);
      return {
        key: aesKey,
        content: encryptedContent
      };
    });
  });
}

function PemToBase64Key(pemPubKey) {
  // pemPubKey should look like this
  // "-----BEGIN PUBLIC KEY-----\n<pubKeyBase64>\n-----END PUBLIC KEY-----\n"
  if (pemPubKey[pemPubKey.length - 1] !== "\n") pemPubKey = pemPubKey + "\n";
  return pemPubKey.split("\n").slice(1, -2).join("");
}

function encryptRSA(pemPubKey, content) {
  var pubKeyBase64 = PemToBase64Key(pemPubKey);
  return crypto.subtle.importKey("spki", stringToArrayBuffer(atob(pubKeyBase64)), ASYM_ALGO, false, ["encrypt"]).then(function (cryptoKey) {
    return crypto.subtle.encrypt({
      name: ASYM_ALGO.name,
      hash: ASYM_ALGO.hash
    }, cryptoKey, stringToArrayBuffer(content)).then(function (encryptedBuffer) {
      return btoa(arrayBufferToString(encryptedBuffer));
    }).catch(function (error) {
      logError("Failed to encrypt with RSA pubKey", error);
      return null;
    });
  }).catch(function (error) {
    logError("Failed to import RSA pubKey", error);
    return null;
  });
}

function DidwwEncrypt(options) {
  var _this = this;

  // todo validate options (allow environment, publicKeys)
  var environment = options.environment;
  var url = options.url || URLS[environment];
  var publicKeysUrl = url + '/public_keys';
  var publicKeys = null;
  var fingerprint = null;

  if (environment === 'test') {
    publicKeys = options.publicKeys;
  }

  this.getPublicKeys = function () {
    if (publicKeys) return new Promise(function (resolve) {
      return resolve(publicKeys);
    });
    return fetchPublicKeys(publicKeysUrl).then(function (result) {
      publicKeys = result;
      return publicKeys;
    });
  };

  this.getFingerprint = function () {
    if (fingerprint) return new Promise(function (resolve) {
      return resolve(fingerprint);
    });
    return _this.getPublicKeys().then(function (keys) {
      return calculateFingerprint(keys);
    }).then(function (result) {
      fingerprint = result;
      return fingerprint;
    });
  };

  this.clearCache = function () {
    publicKeys = null;
    fingerprint = null;
  };

  this.encryptContent = function (fileContent) {
    var asymKeys = null;
    var symKey = null;
    var symEncryptedContent = null;
    var symEncryptedKey = null; // { content, key }

    var encryptedParts = [];
    return _this.getPublicKeys().then(function (result) {
      return asymKeys = result;
    }).then(function (_) {
      return generateKey().then(function (result) {
        return symKey = result;
      });
    }).then(function (_) {
      return encryptAES(symKey, fileContent).then(function (result) {
        symEncryptedContent = result.content;
        symEncryptedKey = result.key;
      });
    }).then(function (_) {
      return encryptRSA(asymKeys[0], symEncryptedKey).then(function (result) {
        return encryptedParts.push(result);
      });
    }).then(function (_) {
      return encryptRSA(asymKeys[1], symEncryptedKey).then(function (result) {
        return encryptedParts.push(result);
      });
    }).then(function (_) {
      return new DidwwEncryptedFile(encryptedParts.concat(symEncryptedContent).join(SEPARATOR));
    });
  };

  this.encryptFile = function (file) {
    return readFileContent(file).then(_this.encryptContent);
  };

  this.encryptArrayBuffer = function (buffer) {
    var binary = arrayBufferToString(buffer);
    return _this.encryptContent(binary);
  };
}

DidwwEncrypt['DidwwEncryptedFile'] = DidwwEncryptedFile;
DidwwEncrypt['SYM_ALGO'] = SYM_ALGO;
DidwwEncrypt['ASYM_ALGO'] = ASYM_ALGO; // export default DidwwEncrypt

module.exports = DidwwEncrypt;
},{"./constants":"iJA9"}],"hpaf":[function(require,module,exports) {
window.DidwwEncrypt = require('./index');
},{"./index":"Focm"}]},{},["hpaf"], null)
//# sourceMappingURL=/browser.js.map