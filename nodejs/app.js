// pkiec - Demo of a Public Key Infrastructure using EC
//-------------------------------------------------------------------------------------------------
// Target: send an 256 bit key asymmetrically encrypted with ECDH, use prime256v1 (= NIST P-256 = secp256r1) for compatibility
// implementation: node-js

'use strict'
const Crypto = require('crypto')

// Receiver keypair initialization
var ecdh = Crypto.createECDH('prime256v1')
ecdh.generateKeys()
var privkey = ecdh.getPrivateKey('base64')      // private key to be stored locally
var pubkey = ecdh.getPublicKey('base64', 'compressed') // compressed for small size (to be expanded when used)
console.log('pubkey:', pubkey)                  // public key is published

// Sender encrypts
var key = Buffer.alloc(32, 0x11)                // key to send (11111... hex)
var token = Buffer.alloc(65)                    // byte 0-31: encrypted key, 32-64: session public key
var ecdh = Crypto.createECDH('prime256v1')
ecdh.generateKeys()                             // random session key
var skey = ecdh.computeSecret(pubkey, 'base64') // derive session private key upon receiver public key
skey.forEach(function (v, i) { token[i] = key[i] ^ v }) // and encrypt
ecdh.getPublicKey(null, 'compressed').copy(token, 32) // append session public key
token = token.toString('base64')
console.log('token:', token)                    // send encrypted key

// Receiver decrypts
token = Buffer.from(token, 'base64')            // receive token
var key = token.slice(0, 32)                    // key to receive
var ecdh = Crypto.createECDH('prime256v1')
ecdh.setPrivateKey(privkey, 'base64')           // load private key from local storage
var skey = ecdh.computeSecret(token.slice(32))  // load session public key
skey.forEach(function (v, i) { key[i] ^= v })   // and decrypt
console.log('key:', key.toString('hex'))        // 11111... hex expected
