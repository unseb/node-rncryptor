const { strict: assert } = require('assert')
const { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes } = require('crypto')
const { Transform } = require('stream')
const PREAMBLE = Buffer.from('RNC\x04')
const CIPHER_ALGORITHM = 'aes-256-cbc'
const HMAC_ALGORITHM = 'sha256'
const PBKDF2_ALGORITHM = 'sha1'
const PBKDF2_ITERATIONS = 10000
const SALT_SIZE = 8
const KEY_SIZE = 32
const IV_SIZE = 16
const HMAC_SIZE = 32
const ERR_HMAC_MISMATCH = 'HMAC mismatch'
const ERR_UNKNOWN_HEADER = 'Unknown header'
const ERR_MESSAGE_TOO_SHORT = 'Message too short'
const ERR_INVALID_CREDETIAL_TYPE = 'Invalid credential type'
class Encryptor extends Transform {
  #engine
  #hmac
  #pendingHeader = PREAMBLE
  constructor(credential, options) {
    super(options)
    if ('password' in credential) {
      const encryptionSalt = randomBytes(SALT_SIZE)
      const hmacSalt = randomBytes(SALT_SIZE)
      credential.encryptionKey = pbkdf2Sync(credential.password, encryptionSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
      credential.hmacKey = pbkdf2Sync(credential.password, hmacSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
      this.#pendingHeader[1] = 1
      this.#pendingHeader = Buffer.concat([this.#pendingHeader, encryptionSalt, hmacSalt])
    }
    assert('encryptionKey' in credential, ERR_INVALID_CREDETIAL_TYPE)
    const iv = randomBytes(IV_SIZE)
    this.#pendingHeader = Buffer.concat([this.#pendingHeader, iv])
    this.#engine = createCipheriv(CIPHER_ALGORITHM, credential.encryptionKey, iv)
    this.#hmac = createHmac(HMAC_ALGORITHM, credential.hmacKey).update(this.#pendingHeader)
  }
  _transform(chunk, encoding, callback) {
    this.push(this.update(chunk, encoding))
    callback()
  }
  _flush(callback) {
    try {
      this.push(this.final())
      callback()
    } catch (e) {
      callback(e)
    }
  }
  update(data, inputEncoding, outputEncoding) {
    let result = this.#handle(this.#engine.update(data, inputEncoding))
    if (outputEncoding && outputEncoding !== 'buffer') return result.toString(outputEncoding)
    return result
  }
  final(outputEncoding) {
    const result = Buffer.concat([this.#handle(this.#engine.final()), this.#hmac.digest()])
    if (outputEncoding && outputEncoding !== 'buffer') return result.toString(outputEncoding)
    return result
  }
  #handle(data) {
    this.#hmac.update(data)
    let result = data
    if (this.#pendingHeader) {
      result = Buffer.concat([this.#pendingHeader, result])
      this.#pendingHeader = null
    }
    return result
  }
}
function createPasswordBasedEncryptor(password, options) {
  return new Encryptor({ password }, options)
}
function createKeyBasedEncryptor(encryptionKey, hmacKey, options) {
  return new Encryptor({ encryptionKey, hmacKey }, options)
}
class Decryptor extends Transform {
  static canDecrypt(preamble) {
    assert(preamble.length >= PREAMBLE_SIZE)
    return preamble[0] == FORMAT_VERSION
  }
  #buffer = Buffer.alloc(0)
  #credential
  #engine
  #hmac
  constructor(credential, options) {
    super(options)
    assert('encryptionKey' in credential || 'password' in credential, ERR_INVALID_CREDETIAL_TYPE)
    this.#credential = credential
  }
  _transform(chunk, encoding, callback) {
    this.push(this.update(chunk, encoding))
    callback()
  }
  _flush(callback) {
    try {
      this.push(this.final())
      callback()
    } catch (e) {
      callback(e)
    }
  }
  update(data, inputEncoding, outputEncoding) {
    let result
    if (!data.length) return Buffer.alloc(0)
    if (typeof data === 'string') data = Buffer.from(data, inputEncoding)
    const previousLength = this.#buffer.length
    const movedSize = this.minimalBufferSize - this.#buffer.length
    this.#buffer = Buffer.concat([this.#buffer, data.subarray(0, movedSize)])
    data = data.subarray(movedSize)
    let offset = 0
    const shouldCheck = (length) => previousLength < (offset += length) && this.#buffer.length >= offset
    if (shouldCheck(PREAMBLE_SIZE)) assert(Decryptor.canDecrypt(this.#buffer), ERR_UNKNOWN_HEADER)
    if (shouldCheck(1)) assert('password' in this.#credential ? 1 : 0, ERR_INVALID_CREDETIAL_TYPE)
    if ('password' in this.#credential && shouldCheck(2 * SALT_SIZE)) {
      const encryptionSalt = this.#buffer.subarray(offset - 2 * SALT_SIZE, offset - SALT_SIZE)
      const hmacSalt = this.#buffer.subarray(offset - SALT_SIZE, offset)
      this.#credential.encryptionKey = pbkdf2Sync(this.#credential.password, encryptionSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
      this.#credential.hmacKey = pbkdf2Sync(this.#credential.password, hmacSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
    }
    if (!this.#hmac && 'hmacKey' in this.#credential) this.#hmac = createHmac(HMAC_ALGORITHM, this.#credential.hmacKey)
    if (shouldCheck(IV_SIZE)) {
      const iv = this.#buffer.subarray(offset - IV_SIZE, offset)
      this.#engine = createDecipheriv(CIPHER_ALGORITHM, this.#credential.encryptionKey, iv)
      this.#hmac.update(this.#buffer.subarray(0, offset))
    }
    if (this.#buffer.length >= this.minimalBufferSize) {
      const concat = Buffer.concat([this.#buffer.subarray(this.requiredHeaderSize), data])
      const overflow = concat.subarray(0, -HMAC_SIZE)
      this.#buffer.fill(concat.subarray(-HMAC_SIZE), this.requiredHeaderSize)
      this.#hmac.update(overflow)
      result = this.#engine.update(overflow)
    }
    if (outputEncoding && outputEncoding !== 'buffer') return result.toString(outputEncoding)
    return result
  }
  final(outputEncoding) {
    assert(this.#buffer.length >= this.minimalBufferSize, ERR_MESSAGE_TOO_SHORT)
    const originalHmac = this.#buffer.subarray(-HMAC_SIZE)
    const computedHmac = this.#hmac.digest()
    assert(computedHmac.equals(originalHmac), ERR_HMAC_MISMATCH)
    const result = this.#engine.final()
    if (outputEncoding && outputEncoding !== 'buffer') return result.toString(outputEncoding)
    return result
  }
  get requiredHeaderSize() {
    let length = PREAMBLE_SIZE + 1 + IV_SIZE
    if ('password' in this.#credential) length += 2 * SALT_SIZE
    return length
  }
  get minimalBufferSize() {
    return this.requiredHeaderSize + HMAC_SIZE
  }
}
function createPasswordBasedDecryptor(password, options) {
  return new Decryptor({ password }, options)
}
function createKeyBasedDecryptor(encryptionKey, hmacKey, options) {
  return new Decryptor({ encryptionKey, hmacKey }, options)
}
module.exports = {
  Decryptor,
  Encryptor,
  createKeyBasedDecryptor,
  createKeyBasedEncryptor,
  createPasswordBasedDecryptor,
  createPasswordBasedEncryptor
}