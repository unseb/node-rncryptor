const { Encryptor, Decryptor } = require('./v2')

const vectors = [
  {
    title: 'Multi-block',
    password: 'password',
    encryptionSaltHex: '97076dc661b6e0ce',
    hmacSaltHex: '9da3bb43d95bcd45',
    ivHex: 'ee396d39e342ffdb679b270dcd9c557c',
    plaintextHex: '546869732069732061206c6f6e676572207465737420766563746f7220696e74656e64656420746f206265206c6f6e676572207468616e206f6e6520626c6f636b2e',
    ciphertextHex: '020197076dc661b6e0ce9da3bb43d95bcd45ee396d39e342ffdb679b270dcd9c557c37055fffcc1b663b1e6b8c5694dbb96d97a3ac0fa3f355db6668c5a8a2a06f10056ce92384a618a35bf0fa9eb612b0b4fa72f749f76e2f728c16574dc2f15b7cec1786d291c2135f932ddc5a34d9eafd6b45f99491ac23c34299af0be68a43e6e8113bb748fbc19bcad638ea79b07309'
  }
]

describe.each(vectors)('$title', ({ password, encryptionSaltHex, hmacSaltHex, ivHex, plaintextHex, ciphertextHex }) => {
  const encryptionSalt = Buffer.from(encryptionSaltHex, 'hex')
  const hmacSalt = Buffer.from(hmacSaltHex, 'hex')
  const iv = Buffer.from(ivHex, 'hex')
  test('Encryption', () => {
    const encryptor = new Encryptor({ password, encryptionSalt, hmacSalt, iv })
    const encryptedHex = encryptor.update(plaintextHex, 'hex', 'hex') + encryptor.final('hex')
    expect(encryptedHex).toBe(ciphertextHex)
  })
  test('Decryption', () => {
    const encryptor = new Decryptor({ password })
    const decryptedHex = encryptor.update(ciphertextHex, 'hex', 'hex') + encryptor.final('hex')
    expect(decryptedHex).toBe(plaintextHex)
  })
})
