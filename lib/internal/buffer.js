const { Transform } = require('stream')
class OverflowingBuffer extends Transform {
  #buffer = Buffer.alloc(0)
  constructor (capacity, options) {
    super(options)
    this.capacity = capacity
  }

  _transform (chunk, encoding, callback) {
    this.push(this.update(chunk, encoding))
    callback()
  }

  _flush (callback) {
    try {
      this.push(this.final())
      callback()
    } catch (e) {
      callback(e)
    }
  }

  update (data, inputEncoding, outputEncoding) {
    if (typeof data === 'string') data = Buffer.from(data, inputEncoding)
    let result
    if (data.length >= this.capacity) {
      result = Buffer.concat([this.#buffer, data.subarray(0, -this.capacity)])
      this.#buffer = data.subarray(-this.capacity)
    } else if (data.length + this.#buffer.length >= this.capacity) {
      result = this.#buffer.subarray(0, data.length - this.capacity)
      this.#buffer = Buffer.concat([
        this.#buffer.subarray(data.length - this.capacity),
        data
      ])
    } else {
      result = Buffer.alloc(0)
      this.#buffer = Buffer.concat([this.#buffer, data])
    }
    if (outputEncoding && outputEncoding !== 'buffer') { return result.toString(outputEncoding) }
    return result
  }

  final (outputEncoding) {
    const result = this.#buffer
    this.#buffer = Buffer.alloc(0)
    if (outputEncoding && outputEncoding !== 'buffer') { return result.toString(outputEncoding) }
    return result
  }
}
module.exports = {
  OverflowingBuffer
}
