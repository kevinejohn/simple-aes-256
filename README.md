# Simple aes-256-ctr

[![NPM Package](https://img.shields.io/npm/v/simple-aes-256.svg?style=flat-square)](https://www.npmjs.org/package/simple-aes-256)

## Use

`npm install --save simple-aes-256`

```
const SimpleAes = require('simple-aes-256')

const message = 'This is some message'
const secret = 'a very secret password'

const encrypted = SimpleAes.encrypt(secret, message)
const decrypted = SimpleAes.decrypt(secret, encrypted)
// decrypted === message
```
