const assert = require('assert')
const SimpleAes = require('./index')

let message = 'This is a test message'
let secret = 'a very secret password'

let encrypted = SimpleAes.encrypt(secret, message)
let decrypted = SimpleAes.decrypt(secret, encrypted)
assert.equal(decrypted.toString(), message)

message = Buffer.from(message)
secret = Buffer.from(secret)

encrypted = SimpleAes.encrypt(secret, message)
decrypted = SimpleAes.decrypt(secret, encrypted)
assert.equal(Buffer.compare(decrypted, message), 0)

const crypto = require('crypto')
const hashedSecret = crypto.randomBytes(32)
encrypted = SimpleAes.encryptRaw(hashedSecret, message)
decrypted = SimpleAes.decryptRaw(hashedSecret, encrypted)
assert.equal(Buffer.compare(decrypted, message), 0)
