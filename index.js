const assert = require("assert/strict");
const { Transform } = require("stream");
const {
  ERR_INVALID_CREDETIAL_TYPE,
  ERR_MESSAGE_TOO_SHORT,
  ERR_UNKNOWN_HEADER,
} = require("./lib/internal/errors").codes;
const v2 = require("./lib/v2");
const v3 = require("./lib/v3");
function createKeyBasedEncryptor(encryptionKey, hmacKey, options) {
  return new v3.Encryptor({ encryptionKey, hmacKey }, options);
}
function createPasswordBasedEncryptor(password, options) {
  return new v3.Encryptor({ password }, options);
}
class Decryptor extends Transform {
  #credential;
  #engines = [v2.Decryptor, v3.Decryptor];
  #engine;
  constructor(credential, options) {
    super(options);
    assert(
      "encryptionKey" in credential || "password" in credential,
      new ERR_INVALID_CREDETIAL_TYPE()
    );
    this.#credential = credential;
  }
  _transform(chunk, encoding, callback) {
    this.push(this.update(chunk, encoding));
    callback();
  }
  _flush(callback) {
    try {
      this.push(this.final());
      callback();
    } catch (e) {
      callback(e);
    }
  }
  update(data, inputEncoding, outputEncoding) {
    if (!this.#engine) this.#determineEngine(data, inputEncoding);
    if (this.#engine)
      return this.#engine.update(data, inputEncoding, outputEncoding);
    return Buffer.alloc(0);
  }
  final(outputEncoding) {
    assert(this.#engine, new ERR_MESSAGE_TOO_SHORT());
    return this.#engine.final(outputEncoding);
  }
  #determineEngine(preamble, inputEncoding) {
    this.#engines = this.#engines.filter((engine) => {
      try {
        return engine.canDecrypt(preamble, inputEncoding);
      } catch (e) {
        return true;
      }
    });
    assert(this.#engines.length, new ERR_UNKNOWN_HEADER());
    if (
      this.#engines.length === 1 &&
      this.#engines[0].canDecrypt(preamble, inputEncoding)
    )
      this.#engine = new this.#engines[0](this.#credential);
  }
}
function createPasswordBasedDecryptor(password, options) {
  return new Decryptor({ password }, options);
}
function createKeyBasedDecryptor(encryptionKey, hmacKey, options) {
  return new Decryptor({ encryptionKey, hmacKey }, options);
}
module.exports = {
  createKeyBasedDecryptor,
  createKeyBasedEncryptor,
  createPasswordBasedDecryptor,
  createPasswordBasedEncryptor,
  v2,
  v3,
};
