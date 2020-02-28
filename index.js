const crypto = require('crypto')

function sha256 (secret) {
  return crypto
    .createHash('sha256')
    .update(secret)
    .digest()
}

function encrypt (secret, text) {
  return encryptRaw(sha256(secret), text)
}
function decrypt (secret, crypted) {
  return decryptRaw(sha256(secret), crypted)
}

function encryptRaw (hashedSecret, text) {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-ctr', hashedSecret, iv)
  return Buffer.concat([iv, cipher.update(text), cipher.final()])
}
function decryptRaw (hashedSecret, crypted) {
  const iv = crypted.slice(0, 16)
  const decipher = crypto.createCipheriv('aes-256-ctr', hashedSecret, iv)
  return Buffer.concat([decipher.update(crypted.slice(16)), decipher.final()])
}

module.exports = {
  sha256,
  encrypt,
  decrypt,
  encryptRaw,
  decryptRaw
}
