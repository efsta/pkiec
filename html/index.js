// Target: send an 256 bit key asymmetrically encrypted with ECDH, use prime256v1 (= NIST P-256 = secp256r1) for compatibility
// implementation: html5

'use strict'

async function onload() {

    var recv = await init()

    setInterval(async function () {
        try {
            console.time('token')
            var key = new Uint8Array(32).fill(0x11) // key to send (11111... hex)
            var token = await send(key, recv.pubkey)
            var key2 = await receive(token, recv.privkey)
            if (hex(key2) != hex(key)) throw 'MISMATCH'
            console.timeEnd('token')            // ~ 10ms
            document.write('. ')
        } catch (err) { document.write(err) }
    }, 100)

}

const Crypto = window.crypto.subtle

async function init() {                         // receiver keypair initialization
    var ecdh = await Crypto.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
    var privkey = await Crypto.exportKey('pkcs8', ecdh.privateKey) // private key to be stored locally
    var pubkey = await Crypto.exportKey('raw', ecdh.publicKey)
    pubkey = compress(pubkey)                   // compress for to 33 bytes
    return { privkey: base64(privkey), pubkey: base64(pubkey) }
}

async function send(key, pubkey) {              // sender encrypts
    pubkey = await expand(fromBase64(pubkey))   // expand compressed receiver public key
    var ecpub = await Crypto.importKey('raw', pubkey, { name: 'ECDH', namedCurve: 'P-256'}, false, [])
    var token = new Uint8Array(65)              // byte 0-31: encrypted key, 32-64: session public key
    var ecdh = await Crypto.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
    var skey = await Crypto.deriveBits({ name: 'ECDH', namedCurve: 'P-256', public: ecpub }, ecdh.privateKey, 256)
    skey = new Uint8Array(await Crypto.digest('SHA-256', skey)) // derive session private key
    skey.forEach(function (v, i) { token[i] = key[i] ^ v }) // encrypt (unique session key xor key)
    var spub = await Crypto.exportKey('raw', ecdh.publicKey)
    spub = compress(spub)                       // session public key
    token.set(spub, 32)                         // appended to token
    return base64(token)                        // send encrypted key
}

async function receive(token, privkey) {        // receiver decrypts
    const ecpriv = await Crypto.importKey('pkcs8', fromBase64(privkey).buffer, {name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveBits'])
    token = fromBase64(token)
    var key = token.slice(0, 32)                // key to receive
    var spub = await expand(token.slice(32))    // expand compressed session public key
    spub = await Crypto.importKey('raw', spub, { name: 'ECDH', namedCurve: 'P-256'}, false, [])
    var skey = await Crypto.deriveBits({ name: 'ECDH', namedCurve: 'P-256', public: spub }, ecpriv, 256)
    skey = new Uint8Array(await Crypto.digest('SHA-256', skey)) // derive session private key
    skey.forEach(function (v, i) { key[i] ^= v }) // decrypt
    return key
}

// Helpers
function base64(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))) } // ArrayBuffer to base64 string
function fromBase64(base64) {                   // base64 string to Uint8Array; for ArrayBuffer use fromBase64().buffer
    base64 = base64.replace(/_/g, '/').replace(/-/g, '+') // also accept base64url
    var bin = atob(base64), len = bin.length, r = new Uint8Array(len)
    for (var i = 0; i < len; i++) r[i] = bin.charCodeAt(i)
    return r
}
function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), x => ('0' + x.toString(16)).slice(-2)).join('') } // ArrayBuffer to hex string
function fromHex(hex) { return new Uint8Array(hex.match(/.{1,2}/g).map(x => parseInt(x, 16))) }
function assert(condition, message) { if (!condition) throw message }

// ECDH public key compression
function compress(pubkey) {                     // compress ECDH public key
    var r = new Uint8Array(pubkey.slice(0, 33)) // use pubkey.x only
    assert(pubkey.byteLength == 65 && r[0] == 4, 'invalid EC public key')
    var signY = new Uint8Array(pubkey.slice(64))[0] & 0x01 // extract pubkey.y sign in first bit
    r[0] = 2 + signY                            // encode in byte[0]
    return r
}

var P256
async function expand(pubkey) {                 // expand Uint8Array ECDH public key (based on https://stackoverflow.com/questions/17171542/algorithm-for-elliptic-curve-point-compression/30431547#30431547)
    assert(pubkey.length == 33 && (pubkey[0] == 2 || pubkey[0] == 3), 'invalid EC compressed key')
//    if (!bigInt) bigInt = await import('./BigInteger.min.js') // import on demand 
    if (!P256) {                                // initialization
        var two = bigInt(2)                     // http://peterolson.github.com/BigInteger.js/BigInteger.min.js
        P256 = {                                // constants for P-256 curve
            prime: two.pow(256).subtract(two.pow(224)).add(two.pow(192)).add(two.pow(96)).subtract(1),
            b: bigInt('41058363725152142129326129780047268409114441015993725554835256314039467401291')
        }
        P256.pIdent = P256.prime.add(1).divide(4)
    }
    var yminus = pubkey[0] == 3 ? true : false  // byte[0]: 2 or 3 (4 indicates an uncompressed key, and anything else is invalid)
    var xbig = bigInt(hex(pubkey.slice(1)), 16) // import x
    var ybig = xbig.pow(3).subtract(xbig.multiply(3)).add(P256.b).modPow(P256.pIdent, P256.prime) // y^2 = x^3 - 3x + b
    if (ybig.isOdd() != yminus) ybig = P256.prime.subtract(ybig) // invert if parity doesn't match - it's the other root
    var y = ybig.toString(16)                   // hex string
    if (y.length < 64) y = new Array(64 - y.length + 1).join('0') + y // pad with '0'
    var r = new Uint8Array(65)                  // expanded key is 65 bytes
    r.set(pubkey)                               // byte[1-32]: x
    r[0] = 4                                    // byte[0]: indicator
    r.set(fromHex(y), 33)                       // byte[33-64]: y
    return r.buffer                             // return ArrayBuffer
}
