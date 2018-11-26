# pkiec - Demo of a Public Key Infrastructure using EC

---
## Target

Send an 256 bit key asymmetrically encrypted with ECDH.

Use prime256v1 (= NIST P-256 = secp256r1) for compatibility with browser [webcrypto](https://github.com/diafygi/webcrypto-examples#ecdh).

Use EC public key compression.

At the moment 2 implementation examples exist:

* [javascript nodejs](https://github.com/efsta/pkiec/blob/master/nodejs/app.js)
* [javascript html using Webcrypto](https://github.com/efsta/pkiec/tree/master/html)

## License
MIT
