const crypto = require('crypto-browserify')

function encrypt (secret, text) {
  const hashedSecret = crypto
    .createHash('sha256')
    .update(secret)
    .digest('buffer')
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-ctr', hashedSecret, iv)
  let crypted = iv.toString('binary')
  crypted += cipher.update(text, 'binary', 'binary')
  crypted += cipher.final('binary')
  return Buffer.from(crypted, 'binary')
}
function decrypt (secret, crypted) {
  const hashedSecret = crypto
    .createHash('sha256')
    .update(secret)
    .digest('buffer')
  const iv = crypted.slice(0, 16)
  const decipher = crypto.createCipheriv('aes-256-ctr', hashedSecret, iv)
  let text = decipher.update(crypted.slice(16), 'binary', 'binary')
  text += decipher.final('binary')
  return text
}

module.exports = {
  encrypt,
  decrypt
}
