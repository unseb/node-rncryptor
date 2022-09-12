# node-rncryptor

JavaScript implementation of RNCryptor

## Supported formats

| Format version | Encryption method         |
| :------------: | :------------------------ |
|       2        | Key based, Password based |
|       3        | Key based, Password based |

## Usage

This package attempts to emulate the Node.js crypto API. You can see how similar `createPasswordEncryptor` is to `createCipheriv`:

```javascript
const { createPasswordBasedEncryptor } = require('rncryptor')

const original = 'The quick brown fox jumps over a lazy dog. 1234567890'
const password = '123456'

const encryptor = createPasswordBasedEncryptor(password)

let encrypted = encryptor.update(original, 'utf-8', 'hex')
encrypted += encryptor.final('hex')

console.log(encrypted)
```

This also applies to the corresponding decryptors:

```javascript
// ...
const { createPasswordBasedDecryptor } = require('rncryptor')

const decryptor = createPasswordBasedDecryptor(password)

let decrypted = decryptor.update(encrypted, 'hex', 'utf-8')
decrypted += decryptor.final('utf-8')

console.log(decrypted)
// Prints: The quick brown fox jumps over a lazy dog. 1234567890
```

### Use specific version format

By default, RNCryptor uses the latest format version when encrypting and automatically guesses the version format when decrypting. If you want to use specific format version, append the format version while importing:

```javascript
const {
  createPasswordBasedEncryptor,
  createPasswordBasedDecryptor
} = require("rncryptor").v2
```

## Todos

- Migrate to TypeScript
- Add inline JSDoc
- Create browser supported builds
- Support older Node.js versions
- Add v4 format support
