const aes = require('browserify-aes')

function randomBytes (size) {
  if (typeof window === 'undefined') {
    return require('crypto').randomBytes(size)
  } else {
    let crypto
    if (window.crypto && window.crypto.getRandomValues) {
      crypto = window.crypto
    } else if (window.msCrypto && window.msCrypto.getRandomValues) {
      crypto = window.msCrypto // internet explorer
    } else {
      throw new Error('window.crypto.getRandomValues not available')
    }
    const buf = new Uint8Array(size)
    crypto.getRandomValues(buf)
    return Buffer.from(buf)
  }
}

function sha256 (input) {
  if (typeof window === 'undefined') {
    return require('crypto')
      .createHash('sha256')
      .update(input)
      .digest()
  } else {
    return require('hash.js')
      .sha256()
      .update(input)
      .digest()
  }
}

function encrypt (secret, text) {
  return encryptRaw(sha256(secret), text)
}
function decrypt (secret, crypted) {
  return decryptRaw(sha256(secret), crypted)
}

function encryptRaw (hashedSecret, text) {
  const iv = randomBytes(16)
  const cipher = aes.createCipheriv('aes-256-ctr', hashedSecret, iv)
  return Buffer.concat([iv, cipher.update(text), cipher.final()])
}
function decryptRaw (hashedSecret, crypted) {
  const iv = crypted.slice(0, 16)
  crypted = crypted.slice(16)
  const decipher = aes.createCipheriv('aes-256-ctr', hashedSecret, iv)
  return Buffer.concat([decipher.update(crypted), decipher.final()])
}

module.exports = {
  sha256,
  encrypt,
  decrypt,
  encryptRaw,
  decryptRaw
}
