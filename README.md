# pkiec - Demo of a Public Key Infrastructure using ECDH

---
## Target

Send an 256 bit key asymmetrically encrypted with ECDH, basically following [ECIES/ECAES](https://cseweb.ucsd.edu/~mihir/papers/dhaes.pdf)

Use prime256v1 (= NIST P-256 = secp256r1) for compatibility with browser [Web Crypto API](https://github.com/diafygi/webcrypto-examples#ecdh).

Use EC public key compression.

At the moment 2 implementation examples exist:

* [javascript nodejs](https://github.com/efsta/pkiec/blob/master/nodejs/app.js)
* [javascript html using Web Crypto API](https://github.com/efsta/pkiec/tree/master/html)

## License
MIT
