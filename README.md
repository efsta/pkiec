pkiecpkiec - Demo of a Public Key Infrastructure using EC

---
Target:

Send an 256 bit key asymmetrically encrypted with ECDH.

Use prime256v1 (= NIST P-256 = secp256r1) for compatibility with browser Webcrypto.

Use EC public key compression.

At the moment 2 implementation examples exist:

* javascript nodejs
* javascript html using Webcrypto
