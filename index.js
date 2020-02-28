const crypto = require('crypto')

function encrypt (secret, text) {
  const hashedSecret = crypto
    .createHash('sha256')
    .update(secret)
    .digest()
  return encryptRaw(hashedSecret, text)
}
function decrypt (secret, crypted) {
  const hashedSecret = crypto
    .createHash('sha256')
    .update(secret)
    .digest()
  return decryptRaw(hashedSecret, crypted)
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
  encrypt,
  decrypt,
  encryptRaw,
  decryptRaw
}
