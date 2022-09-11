const { strict: assert } = require('assert')
const { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes } = require('crypto')
const { Transform } = require('stream')
const { OverflowingBuffer, errors: { ERR_HMAC_MISMATCH, ERR_INVALID_CREDETIAL_TYPE, ERR_MESSAGE_TOO_SHORT, ERR_UNKNOWN_HEADER } } = require('./internal')
const MAGIC = Buffer.from([2])
const CIPHER_ALGORITHM = 'aes-256-cbc'
const HMAC_ALGORITHM = 'sha256'
const PBKDF2_ALGORITHM = 'sha1'
const PBKDF2_ITERATIONS = 10000
const SALT_SIZE = 8
const KEY_SIZE = 32
const IV_SIZE = 16
const HMAC_SIZE = 32
class Encryptor extends Transform {
  #engine
  #hmac
  #pendingHeader
  constructor(credential, options) {
    super(options)
    if ('password' in credential) {
      if (typeof credential.password !== 'string') credential.password = credential.password.toString()
      credential.password = Buffer.alloc(credential.password.length, credential.password)
      const encryptionSalt = randomBytes(SALT_SIZE)
      const hmacSalt = randomBytes(SALT_SIZE)
      credential.encryptionKey = pbkdf2Sync(credential.password, encryptionSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
      credential.hmacKey = pbkdf2Sync(credential.password, hmacSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
      this.#pendingHeader = Buffer.concat([MAGIC, Buffer.from([1]), encryptionSalt, hmacSalt])
    } else this.#pendingHeader = Buffer.concat([MAGIC, Buffer.from([0])])
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
  #buffer = new OverflowingBuffer(HMAC_SIZE)
  #credential
  #engine
  #header = Buffer.alloc(0)
  #hmac
  static isCompatible(preamble, inputEncoding) {
    if (typeof preamble === 'string') preamble = Buffer.from(preamble, inputEncoding)
    assert(preamble.length >= MAGIC.length, ERR_MESSAGE_TOO_SHORT)
    return preamble.subarray(0, MAGIC.length).equals(MAGIC)
  }
  constructor(credential, options) {
    super(options)
    assert('encryptionKey' in credential || 'password' in credential, ERR_INVALID_CREDETIAL_TYPE)
    if ('password' in credential) {
      if (typeof credential.password !== 'string') credential.password = credential.password.toString()
      credential.password = Buffer.alloc(credential.password.length, credential.password)
    }
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
    let result = Buffer.alloc(0)
    if (!data.length) return result
    if (typeof data === 'string') data = Buffer.from(data, inputEncoding)
    if (this.#header.length < this.requiredHeaderSize) data = this.#parseHeader(data)
    if (this.#header.length === this.requiredHeaderSize) {
      const overflow = this.#buffer.update(data)
      this.#hmac.update(overflow)
      result = this.#engine.update(overflow)
    }
    if (outputEncoding && outputEncoding !== 'buffer') return result.toString(outputEncoding)
    return result
  }
  final(outputEncoding) {
    const originalHmac = this.#buffer.final()
    assert(originalHmac.length === HMAC_SIZE, ERR_MESSAGE_TOO_SHORT)
    const computedHmac = this.#hmac.digest()
    assert(computedHmac.equals(originalHmac), ERR_HMAC_MISMATCH)
    const result = this.#engine.final()
    if (outputEncoding && outputEncoding !== 'buffer') return result.toString(outputEncoding)
    return result
  }
  get requiredHeaderSize() {
    let length = MAGIC.length + 1 + IV_SIZE
    if ('password' in this.#credential) length += 2 * SALT_SIZE
    return length
  }
  #parseHeader(data) {
    const previousLength = this.#header.length
    const movedSize = this.requiredHeaderSize - this.#header.length
    this.#header = Buffer.concat([this.#header, data.subarray(0, movedSize)])
    data = data.subarray(movedSize)
    // Scan through unread data
    let offset = 0
    // Check whether data fragment hasn't been read and readable
    const shouldCheck = (length) => previousLength < (offset += length) && this.#header.length >= offset
    if (shouldCheck(MAGIC.length)) assert(this.#header.subarray(0, MAGIC.length).equals(MAGIC), ERR_UNKNOWN_HEADER)
    if (shouldCheck(1)) assert('password' in this.#credential ? 1 : 0, ERR_INVALID_CREDETIAL_TYPE)
    if ('password' in this.#credential && shouldCheck(2 * SALT_SIZE)) {
      const encryptionSalt = this.#header.subarray(offset - 2 * SALT_SIZE, offset - SALT_SIZE)
      const hmacSalt = this.#header.subarray(offset - SALT_SIZE, offset)
      this.#credential.encryptionKey = pbkdf2Sync(this.#credential.password, encryptionSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
      this.#credential.hmacKey = pbkdf2Sync(this.#credential.password, hmacSalt, PBKDF2_ITERATIONS, KEY_SIZE, PBKDF2_ALGORITHM)
    }
    if (!this.#hmac && 'hmacKey' in this.#credential) this.#hmac = createHmac(HMAC_ALGORITHM, this.#credential.hmacKey)
    if (shouldCheck(IV_SIZE)) {
      const iv = this.#header.subarray(offset - IV_SIZE, offset)
      this.#engine = createDecipheriv(CIPHER_ALGORITHM, this.#credential.encryptionKey, iv)
      this.#hmac.update(this.#header.subarray(0, offset))
    }
    return data
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
  MAGIC,
  createKeyBasedDecryptor,
  createKeyBasedEncryptor,
  createPasswordBasedDecryptor,
  createPasswordBasedEncryptor
}