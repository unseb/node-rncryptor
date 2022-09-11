const util = require("util");
const messages = new Map();
const codes = {};
function getMessage(key, args) {
  const msg = messages.get(key);
  if (typeof msg === "function") return msg(...args);
  return util.format(msg, ...args);
}
function makeRNCryptorErrorWithCode(Base, key) {
  return function RNCryptorError(...args) {
    const error = new Base(getMessage(key, args));
    Object.defineProperty(error, "toString", {
      value: function () {
        return `${this.name} [${key}]: ${this.message}`;
      },
      writable: true,
      configurable: true,
    });
    error.code = key;
    return error;
  };
}
function E(sym, val, def, ...otherClasses) {
  messages.set(sym, val);
  def = makeRNCryptorErrorWithCode(def, sym);
  otherClasses.forEach(
    (clazz) => (def[clazz.name] = makeRNCryptorErrorWithCode(clazz, sym))
  );
  codes[sym] = def;
}
module.exports = {
  codes,
  E,
  getMessage,
};
E("ERR_HMAC_MISMATCH", "HMAC mismatch.", Error);
E("ERR_UNKNOWN_HEADER", "Unknown header.", Error);
E("ERR_MESSAGE_TOO_SHORT", "Message too short.", Error);
E("ERR_INVALID_CREDETIAL_TYPE", "Invalid credential type.", TypeError);
