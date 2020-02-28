# Simple aes-256-ctr

[![NPM Package](https://img.shields.io/npm/v/simple-aes-256.svg?style=flat-square)](https://www.npmjs.org/package/simple-aes-256)

## Use

`npm install simple-aes-256`

```
const SimpleAes = require('simple-aes-256')

const message = 'This is some message'
const secret = 'a very secret password'

// encrypt and decrypt functions sha256 hash the secret which can be any string or buffer
let encrypted = SimpleAes.encrypt(secret, message)
let decrypted = SimpleAes.decrypt(secret, encrypted)
// decrypted.toString() === message


const hashedSecret = require('crypto').randomBytes(32)

// encryptRaw and decryptRaw functions only accept a 32 byte buffer secret
encrypted = SimpleAes.encryptRaw(hashedSecret, message)
decrypted = SimpleAes.decryptRaw(hashedSecret, encrypted)
// decrypted.toString() === message
```
