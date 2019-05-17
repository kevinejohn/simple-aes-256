const assert = require('assert')
const SimpleAes = require('./index')

const message = 'This is a test message'
const secret = 'a very secret password'

const encrypted = SimpleAes.encrypt(secret, message)
console.log(encrypted)
const decrypted = SimpleAes.decrypt(secret, encrypted)
console.log(decrypted)
assert(decrypted === message)
