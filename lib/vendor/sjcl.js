"use strict";
var sjcl = {
  cipher: {},
  hash: {},
  keyexchange: {},
  mode: {},
  misc: {},
  codec: {},
  exception: {
    corrupt: function(message) {
      this.toString = function() {
        return "CORRUPT: " + this.message;
      };
      this.message = message;
    },
    invalid: function(message) {
      this.toString = function() {
        return "INVALID: " + this.message;
      };
      this.message = message;
    },
    bug: function(message) {
      this.toString = function() {
        return "BUG: " + this.message;
      };
      this.message = message;
    },
    notReady: function(message) {
      this.toString = function() {
        return "NOT READY: " + this.message;
      };
      this.message = message;
    }
  }
};
if (typeof module != "undefined" && module.exports) {
  module.exports = sjcl;
}
sjcl.cipher.aes = function(key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }
  var i,
    j,
    tmp,
    encKey,
    decKey,
    sbox = this._tables[0][4],
    decTable = this._tables[1],
    keyLen = key.length,
    rcon = 1;
  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw new sjcl.exception.invalid("invalid aes key size");
  }
  this._key = [(encKey = key.slice(0)), (decKey = [])];
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i - 1];
    if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
      tmp =
        (sbox[tmp >>> 24] << 24) ^
        (sbox[(tmp >> 16) & 255] << 16) ^
        (sbox[(tmp >> 8) & 255] << 8) ^
        sbox[tmp & 255];
      if (i % keyLen === 0) {
        tmp = (tmp << 8) ^ (tmp >>> 24) ^ (rcon << 24);
        rcon = (rcon << 1) ^ ((rcon >> 7) * 283);
      }
    }
    encKey[i] = encKey[i - keyLen] ^ tmp;
  }
  for (j = 0; i; j++, i--) {
    tmp = encKey[j & 3 ? i : i - 4];
    if (i <= 4 || j < 4) {
      decKey[j] = tmp;
    } else {
      decKey[j] =
        decTable[0][sbox[tmp >>> 24]] ^
        decTable[1][sbox[(tmp >> 16) & 255]] ^
        decTable[2][sbox[(tmp >> 8) & 255]] ^
        decTable[3][sbox[tmp & 255]];
    }
  }
};
sjcl.cipher.aes.prototype = {
  encrypt: function(data) {
    return this._crypt(data, 0);
  },
  decrypt: function(data) {
    return this._crypt(data, 1);
  },
  _tables: [[[], [], [], [], []], [[], [], [], [], []]],
  _precompute: function() {
    var encTable = this._tables[0],
      decTable = this._tables[1],
      sbox = encTable[4],
      sboxInv = decTable[4],
      i,
      x,
      xInv,
      d = [],
      th = [],
      x2,
      x4,
      x8,
      s,
      tEnc,
      tDec;
    for (i = 0; i < 256; i++) {
      th[(d[i] = (i << 1) ^ ((i >> 7) * 283)) ^ i] = i;
    }
    for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
      s = xInv ^ (xInv << 1) ^ (xInv << 2) ^ (xInv << 3) ^ (xInv << 4);
      s = (s >> 8) ^ (s & 255) ^ 99;
      sbox[x] = s;
      sboxInv[s] = x;
      x8 = d[(x4 = d[(x2 = d[x])])];
      tDec = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
      tEnc = (d[s] * 0x101) ^ (s * 0x1010100);
      for (i = 0; i < 4; i++) {
        encTable[i][x] = tEnc = (tEnc << 24) ^ (tEnc >>> 8);
        decTable[i][s] = tDec = (tDec << 24) ^ (tDec >>> 8);
      }
    }
    for (i = 0; i < 5; i++) {
      encTable[i] = encTable[i].slice(0);
      decTable[i] = decTable[i].slice(0);
    }
  },
  _crypt: function(input, dir) {
    if (input.length !== 4) {
      throw new sjcl.exception.invalid("invalid aes block size");
    }
    var key = this._key[dir],
      a = input[0] ^ key[0],
      b = input[dir ? 3 : 1] ^ key[1],
      c = input[2] ^ key[2],
      d = input[dir ? 1 : 3] ^ key[3],
      a2,
      b2,
      c2,
      nInnerRounds = key.length / 4 - 2,
      i,
      kIndex = 4,
      out = [0, 0, 0, 0],
      table = this._tables[dir],
      t0 = table[0],
      t1 = table[1],
      t2 = table[2],
      t3 = table[3],
      sbox = table[4];
    for (i = 0; i < nInnerRounds; i++) {
      a2 =
        t0[a >>> 24] ^
        t1[(b >> 16) & 255] ^
        t2[(c >> 8) & 255] ^
        t3[d & 255] ^
        key[kIndex];
      b2 =
        t0[b >>> 24] ^
        t1[(c >> 16) & 255] ^
        t2[(d >> 8) & 255] ^
        t3[a & 255] ^
        key[kIndex + 1];
      c2 =
        t0[c >>> 24] ^
        t1[(d >> 16) & 255] ^
        t2[(a >> 8) & 255] ^
        t3[b & 255] ^
        key[kIndex + 2];
      d =
        t0[d >>> 24] ^
        t1[(a >> 16) & 255] ^
        t2[(b >> 8) & 255] ^
        t3[c & 255] ^
        key[kIndex + 3];
      kIndex += 4;
      a = a2;
      b = b2;
      c = c2;
    }
    for (i = 0; i < 4; i++) {
      out[dir ? 3 & -i : i] =
        (sbox[a >>> 24] << 24) ^
        (sbox[(b >> 16) & 255] << 16) ^
        (sbox[(c >> 8) & 255] << 8) ^
        sbox[d & 255] ^
        key[kIndex++];
      a2 = a;
      a = b;
      b = c;
      c = d;
      d = a2;
    }
    return out;
  }
};
sjcl.bitArray = {
  bitSlice: function(a, bstart, bend) {
    a = sjcl.bitArray
      ._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31))
      .slice(1);
    return bend === undefined ? a : sjcl.bitArray.clamp(a, bend - bstart);
  },
  extract: function(a, bstart, blength) {
    var x,
      sh = Math.floor((-bstart - blength) & 31);
    if (((bstart + blength - 1) ^ bstart) & -32) {
      x =
        (a[(bstart / 32) | 0] << (32 - sh)) ^ (a[(bstart / 32 + 1) | 0] >>> sh);
    } else {
      x = a[(bstart / 32) | 0] >>> sh;
    }
    return x & ((1 << blength) - 1);
  },
  concat: function(a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }
    var out,
      i,
      last = a1[a1.length - 1],
      shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(
        a2,
        shift,
        last | 0,
        a1.slice(0, a1.length - 1)
      );
    }
  },
  bitLength: function(a) {
    var l = a.length,
      x;
    if (l === 0) {
      return 0;
    }
    x = a[l - 1];
    return (l - 1) * 32 + sjcl.bitArray.getPartial(x);
  },
  clamp: function(a, len) {
    if (a.length * 32 < len) {
      return a;
    }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l - 1] = sjcl.bitArray.partial(
        len,
        a[l - 1] & (0x80000000 >> (len - 1)),
        1
      );
    }
    return a;
  },
  partial: function(len, x, _end) {
    if (len === 32) {
      return x;
    }
    return (_end ? x | 0 : x << (32 - len)) + len * 0x10000000000;
  },
  getPartial: function(x) {
    return Math.round(x / 0x10000000000) || 32;
  },
  equal: function(a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0,
      i;
    for (i = 0; i < a.length; i++) {
      x |= a[i] ^ b[i];
    }
    return x === 0;
  },
  _shiftRight: function(a, shift, carry, out) {
    var i,
      last2 = 0,
      shift2;
    if (out === undefined) {
      out = [];
    }
    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }
    for (i = 0; i < a.length; i++) {
      out.push(carry | (a[i] >>> shift));
      carry = a[i] << (32 - shift);
    }
    last2 = a.length ? a[a.length - 1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(
      sjcl.bitArray.partial(
        (shift + shift2) & 31,
        shift + shift2 > 32 ? carry : out.pop(),
        1
      )
    );
    return out;
  },
  _xor4: function(x, y) {
    return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
  }
};
sjcl.codec.utf8String = {
  fromBits: function(arr) {
    var out = "",
      bl = sjcl.bitArray.bitLength(arr),
      i,
      tmp;
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4];
      }
      out += String.fromCharCode(tmp >>> 24);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },
  toBits: function(str) {
    str = unescape(encodeURIComponent(str));
    var out = [],
      i,
      tmp = 0;
    for (i = 0; i < str.length; i++) {
      tmp = (tmp << 8) | str.charCodeAt(i);
      if ((i & 3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i & 3) {
      out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
    }
    return out;
  }
};
sjcl.codec.hex = {
  fromBits: function(arr) {
    var out = "",
      i,
      x;
    for (i = 0; i < arr.length; i++) {
      out += ((arr[i] | 0) + 0xf00000000000).toString(16).substr(4);
    }
    return out.substr(0, sjcl.bitArray.bitLength(arr) / 4);
  },
  toBits: function(str) {
    var i,
      out = [],
      len;
    str = str.replace(/\s|0x/g, "");
    len = str.length;
    str = str + "00000000";
    for (i = 0; i < str.length; i += 8) {
      out.push(parseInt(str.substr(i, 8), 16) ^ 0);
    }
    return sjcl.bitArray.clamp(out, len * 4);
  }
};
sjcl.codec.base64 = {
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  fromBits: function(arr, _noEquals, _url) {
    var out = "",
      i,
      bits = 0,
      c = sjcl.codec.base64._chars,
      ta = 0,
      bl = sjcl.bitArray.bitLength(arr);
    if (_url) c = c.substr(0, 62) + "-_";
    for (i = 0; out.length * 6 < bl; ) {
      out += c.charAt((ta ^ (arr[i] >>> bits)) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6 - bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while (out.length & 3 && !_noEquals) {
      out += "=";
    }
    return out;
  },
  toBits: function(str, _url) {
    str = str.replace(/\s|=/g, "");
    var out = [],
      i,
      bits = 0,
      c = sjcl.codec.base64._chars,
      ta = 0,
      x;
    if (_url) c = c.substr(0, 62) + "-_";
    for (i = 0; i < str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ (x >>> bits));
        ta = x << (32 - bits);
      } else {
        bits += 6;
        ta ^= x << (32 - bits);
      }
    }
    if (bits & 56) {
      out.push(sjcl.bitArray.partial(bits & 56, ta, 1));
    }
    return out;
  }
};
sjcl.codec.base64url = {
  fromBits: function(arr) {
    return sjcl.codec.base64.fromBits(arr, 1, 1);
  },
  toBits: function(str) {
    return sjcl.codec.base64.toBits(str, 1);
  }
};
sjcl.codec.base58 = {
  alphabets: "123456789AbCDEFGHJKLMNPQRSTuVWXYZaBcdefghijkmnopqrstUvwxyz",
  BASE: 58,
  ALPHABET_MAP: {},
  LEADER: "1",
  encode: function(a) {
    if (a.length === 0) return "";
    var i, j;
    var digits = [0];
    for (i = 0; i < a.length; i++) {
      for (j = 0; j < digits.length; j++) {
        digits[j] <<= 8;
      }
      digits[0] += a[i];
      var carry = 0;
      for (j = 0; j < digits.length; ++j) {
        digits[j] += carry;
        carry = (digits[j] / this.BASE) | 0;
        digits[j] %= this.BASE;
      }
      while (carry) {
        digits.push(carry % this.BASE);
        carry = (carry / this.BASE) | 0;
      }
    }
    for (i = 0; a[i] === 0 && i < a.length - 1; i++) {
      digits.push(0);
    }
    return digits
      .reverse()
      .map(function(digit) {
        return sjcl.codec.base58.alphabets[digit];
      })
      .join("");
  },
  decode: function(str) {
    for (var i = 0; i < this.alphabets.length; i++) {
      this.ALPHABET_MAP[this.alphabets.charAt(i)] = i;
    }
    if (str.length === 0) {
      return [];
    }
    var i, j;
    var bytes = [0];
    for (i = 0; i < str.length; i++) {
      var c = str[i];
      if (!(c in this.ALPHABET_MAP))
        throw new Error("Non-base" + this.BASE + " character");
      for (j = 0; j < bytes.length; j++) {
        bytes[j] *= this.BASE;
      }
      bytes[0] += this.ALPHABET_MAP[c];
      var carry = 0;
      for (j = 0; j < bytes.length; ++j) {
        bytes[j] += carry;
        carry = bytes[j] >> 8;
        bytes[j] &= 0xff;
      }
      while (carry) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }
    for (i = 0; str[i] === this.LEADER && i < str.length - 1; i++) {
      bytes.push(0);
    }
    return bytes.reverse();
  }
};
sjcl.codec.bytes = {
  fromBits: function(arr) {
    var out = [],
      bl = sjcl.bitArray.bitLength(arr),
      i,
      tmp;
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4];
      }
      out.push(tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },
  toBits: function(bytes) {
    var out = [],
      i,
      tmp = 0;
    for (i = 0; i < bytes.length; i++) {
      tmp = (tmp << 8) | bytes[i];
      if ((i & 3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i & 3) {
      out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
    }
    return out;
  }
};
sjcl.hash.sha256 = function(hash) {
  if (!this._key[0]) {
    this._precompute();
  }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};
sjcl.hash.sha256.hash = function(data) {
  return new sjcl.hash.sha256().update(data).finalize();
};
sjcl.hash.sha256.prototype = {
  blockSize: 512,
  reset: function() {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  update: function(data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i,
      b = (this._buffer = sjcl.bitArray.concat(this._buffer, data)),
      ol = this._length,
      nl = (this._length = ol + sjcl.bitArray.bitLength(data));
    for (i = (512 + ol) & -512; i <= nl; i += 512) {
      this._block(b.splice(0, 16));
    }
    return this;
  },
  finalize: function() {
    var i,
      b = this._buffer,
      h = this._h;
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);
    while (b.length) {
      this._block(b.splice(0, 16));
    }
    this.reset();
    return h;
  },
  _init: [],
  _key: [],
  _precompute: function() {
    var i = 0,
      prime = 2,
      factor;
    function frac(x) {
      return ((x - Math.floor(x)) * 0x100000000) | 0;
    }
    outer: for (; i < 64; prime++) {
      for (factor = 2; factor * factor <= prime; factor++) {
        if (prime % factor === 0) {
          continue outer;
        }
      }
      if (i < 8) {
        this._init[i] = frac(Math.pow(prime, 1 / 2));
      }
      this._key[i] = frac(Math.pow(prime, 1 / 3));
      i++;
    }
  },
  _block: function(words) {
    var i,
      tmp,
      a,
      b,
      w = words.slice(0),
      h = this._h,
      k = this._key,
      h0 = h[0],
      h1 = h[1],
      h2 = h[2],
      h3 = h[3],
      h4 = h[4],
      h5 = h[5],
      h6 = h[6],
      h7 = h[7];
    for (i = 0; i < 64; i++) {
      if (i < 16) {
        tmp = w[i];
      } else {
        a = w[(i + 1) & 15];
        b = w[(i + 14) & 15];
        tmp = w[i & 15] =
          (((a >>> 7) ^ (a >>> 18) ^ (a >>> 3) ^ (a << 25) ^ (a << 14)) +
            ((b >>> 17) ^ (b >>> 19) ^ (b >>> 10) ^ (b << 15) ^ (b << 13)) +
            w[i & 15] +
            w[(i + 9) & 15]) |
          0;
      }
      tmp =
        tmp +
        h7 +
        ((h4 >>> 6) ^
          (h4 >>> 11) ^
          (h4 >>> 25) ^
          (h4 << 26) ^
          (h4 << 21) ^
          (h4 << 7)) +
        (h6 ^ (h4 & (h5 ^ h6))) +
        k[i];
      h7 = h6;
      h6 = h5;
      h5 = h4;
      h4 = (h3 + tmp) | 0;
      h3 = h2;
      h2 = h1;
      h1 = h0;
      h0 =
        (tmp +
          ((h1 & h2) ^ (h3 & (h1 ^ h2))) +
          ((h1 >>> 2) ^
            (h1 >>> 13) ^
            (h1 >>> 22) ^
            (h1 << 30) ^
            (h1 << 19) ^
            (h1 << 10))) |
        0;
    }
    h[0] = (h[0] + h0) | 0;
    h[1] = (h[1] + h1) | 0;
    h[2] = (h[2] + h2) | 0;
    h[3] = (h[3] + h3) | 0;
    h[4] = (h[4] + h4) | 0;
    h[5] = (h[5] + h5) | 0;
    h[6] = (h[6] + h6) | 0;
    h[7] = (h[7] + h7) | 0;
  }
};
sjcl.hash.sha512 = function(hash) {
  if (!this._key[0]) {
    this._precompute();
  }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};
sjcl.hash.sha512.hash = function(data) {
  return new sjcl.hash.sha512().update(data).finalize();
};
sjcl.hash.sha512.prototype = {
  blockSize: 1024,
  reset: function() {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  update: function(data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i,
      b = (this._buffer = sjcl.bitArray.concat(this._buffer, data)),
      ol = this._length,
      nl = (this._length = ol + sjcl.bitArray.bitLength(data));
    for (i = (1024 + ol) & -1024; i <= nl; i += 1024) {
      this._block(b.splice(0, 32));
    }
    return this;
  },
  finalize: function() {
    var i,
      b = this._buffer,
      h = this._h;
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
    for (i = b.length + 4; i & 31; i++) {
      b.push(0);
    }
    b.push(0);
    b.push(0);
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);
    while (b.length) {
      this._block(b.splice(0, 32));
    }
    this.reset();
    return h;
  },
  _init: [],
  _initr: [
    0xbcc908,
    0xcaa73b,
    0x94f82b,
    0x1d36f1,
    0xe682d1,
    0x3e6c1f,
    0x41bd6b,
    0x7e2179
  ],
  _key: [],
  _keyr: [
    0x28ae22,
    0xef65cd,
    0x4d3b2f,
    0x89dbbc,
    0x48b538,
    0x05d019,
    0x194f9b,
    0x6d8118,
    0x030242,
    0x706fbe,
    0xe4b28c,
    0xffb4e2,
    0x7b896f,
    0x1696b1,
    0xc71235,
    0x692694,
    0xf14ad2,
    0x4f25e3,
    0x8cd5b5,
    0xac9c65,
    0x2b0275,
    0xa6e483,
    0x41fbd4,
    0x1153b5,
    0x66dfab,
    0xb43210,
    0xfb213f,
    0xef0ee4,
    0xa88fc2,
    0x0aa725,
    0x03826f,
    0x0e6e70,
    0xd22ffc,
    0x26c926,
    0xc42aed,
    0x95b3df,
    0xaf63de,
    0x77b2a8,
    0xedaee6,
    0x82353b,
    0xf10364,
    0x423001,
    0xf89791,
    0x54be30,
    0xef5218,
    0x65a910,
    0x71202a,
    0xbbd1b8,
    0xd2d0c8,
    0x41ab53,
    0x8eeb99,
    0x9b48a8,
    0xc95a63,
    0x418acb,
    0x63e373,
    0xb2b8a3,
    0xefb2fc,
    0x172f60,
    0xf0ab72,
    0x6439ec,
    0x631e28,
    0x82bde9,
    0xc67915,
    0x72532b,
    0x26619c,
    0xc0c207,
    0xe0eb1e,
    0x6ed178,
    0x176fba,
    0xc898a6,
    0xf90dae,
    0x1c471b,
    0x047d84,
    0xc72493,
    0xc9bebc,
    0x100d4c,
    0x3e42b6,
    0x657e2a,
    0xd6faec,
    0x475817
  ],
  _precompute: function() {
    var i = 0,
      prime = 2,
      factor;
    function frac(x) {
      return ((x - Math.floor(x)) * 0x100000000) | 0;
    }
    function frac2(x) {
      return ((x - Math.floor(x)) * 0x10000000000) & 0xff;
    }
    outer: for (; i < 80; prime++) {
      for (factor = 2; factor * factor <= prime; factor++) {
        if (prime % factor === 0) {
          continue outer;
        }
      }
      if (i < 8) {
        this._init[i * 2] = frac(Math.pow(prime, 1 / 2));
        this._init[i * 2 + 1] =
          (frac2(Math.pow(prime, 1 / 2)) << 24) | this._initr[i];
      }
      this._key[i * 2] = frac(Math.pow(prime, 1 / 3));
      this._key[i * 2 + 1] =
        (frac2(Math.pow(prime, 1 / 3)) << 24) | this._keyr[i];
      i++;
    }
  },
  _block: function(words) {
    var i,
      wrh,
      wrl,
      w = words.slice(0),
      h = this._h,
      k = this._key,
      h0h = h[0],
      h0l = h[1],
      h1h = h[2],
      h1l = h[3],
      h2h = h[4],
      h2l = h[5],
      h3h = h[6],
      h3l = h[7],
      h4h = h[8],
      h4l = h[9],
      h5h = h[10],
      h5l = h[11],
      h6h = h[12],
      h6l = h[13],
      h7h = h[14],
      h7l = h[15];
    var ah = h0h,
      al = h0l,
      bh = h1h,
      bl = h1l,
      ch = h2h,
      cl = h2l,
      dh = h3h,
      dl = h3l,
      eh = h4h,
      el = h4l,
      fh = h5h,
      fl = h5l,
      gh = h6h,
      gl = h6l,
      hh = h7h,
      hl = h7l;
    for (i = 0; i < 80; i++) {
      if (i < 16) {
        wrh = w[i * 2];
        wrl = w[i * 2 + 1];
      } else {
        var gamma0xh = w[(i - 15) * 2];
        var gamma0xl = w[(i - 15) * 2 + 1];
        var gamma0h =
          ((gamma0xl << 31) | (gamma0xh >>> 1)) ^
          ((gamma0xl << 24) | (gamma0xh >>> 8)) ^
          (gamma0xh >>> 7);
        var gamma0l =
          ((gamma0xh << 31) | (gamma0xl >>> 1)) ^
          ((gamma0xh << 24) | (gamma0xl >>> 8)) ^
          ((gamma0xh << 25) | (gamma0xl >>> 7));
        var gamma1xh = w[(i - 2) * 2];
        var gamma1xl = w[(i - 2) * 2 + 1];
        var gamma1h =
          ((gamma1xl << 13) | (gamma1xh >>> 19)) ^
          ((gamma1xh << 3) | (gamma1xl >>> 29)) ^
          (gamma1xh >>> 6);
        var gamma1l =
          ((gamma1xh << 13) | (gamma1xl >>> 19)) ^
          ((gamma1xl << 3) | (gamma1xh >>> 29)) ^
          ((gamma1xh << 26) | (gamma1xl >>> 6));
        var wr7h = w[(i - 7) * 2];
        var wr7l = w[(i - 7) * 2 + 1];
        var wr16h = w[(i - 16) * 2];
        var wr16l = w[(i - 16) * 2 + 1];
        wrl = gamma0l + wr7l;
        wrh = gamma0h + wr7h + (wrl >>> 0 < gamma0l >>> 0 ? 1 : 0);
        wrl += gamma1l;
        wrh += gamma1h + (wrl >>> 0 < gamma1l >>> 0 ? 1 : 0);
        wrl += wr16l;
        wrh += wr16h + (wrl >>> 0 < wr16l >>> 0 ? 1 : 0);
      }
      w[i * 2] = wrh |= 0;
      w[i * 2 + 1] = wrl |= 0;
      var chh = (eh & fh) ^ (~eh & gh);
      var chl = (el & fl) ^ (~el & gl);
      var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      var majl = (al & bl) ^ (al & cl) ^ (bl & cl);
      var sigma0h =
        ((al << 4) | (ah >>> 28)) ^
        ((ah << 30) | (al >>> 2)) ^
        ((ah << 25) | (al >>> 7));
      var sigma0l =
        ((ah << 4) | (al >>> 28)) ^
        ((al << 30) | (ah >>> 2)) ^
        ((al << 25) | (ah >>> 7));
      var sigma1h =
        ((el << 18) | (eh >>> 14)) ^
        ((el << 14) | (eh >>> 18)) ^
        ((eh << 23) | (el >>> 9));
      var sigma1l =
        ((eh << 18) | (el >>> 14)) ^
        ((eh << 14) | (el >>> 18)) ^
        ((el << 23) | (eh >>> 9));
      var krh = k[i * 2];
      var krl = k[i * 2 + 1];
      var t1l = hl + sigma1l;
      var t1h = hh + sigma1h + (t1l >>> 0 < hl >>> 0 ? 1 : 0);
      t1l += chl;
      t1h += chh + (t1l >>> 0 < chl >>> 0 ? 1 : 0);
      t1l += krl;
      t1h += krh + (t1l >>> 0 < krl >>> 0 ? 1 : 0);
      t1l += wrl;
      t1h += wrh + (t1l >>> 0 < wrl >>> 0 ? 1 : 0);
      var t2l = sigma0l + majl;
      var t2h = sigma0h + majh + (t2l >>> 0 < sigma0l >>> 0 ? 1 : 0);
      hh = gh;
      hl = gl;
      gh = fh;
      gl = fl;
      fh = eh;
      fl = el;
      el = (dl + t1l) | 0;
      eh = (dh + t1h + (el >>> 0 < dl >>> 0 ? 1 : 0)) | 0;
      dh = ch;
      dl = cl;
      ch = bh;
      cl = bl;
      bh = ah;
      bl = al;
      al = (t1l + t2l) | 0;
      ah = (t1h + t2h + (al >>> 0 < t1l >>> 0 ? 1 : 0)) | 0;
    }
    h0l = h[1] = (h0l + al) | 0;
    h[0] = (h0h + ah + (h0l >>> 0 < al >>> 0 ? 1 : 0)) | 0;
    h1l = h[3] = (h1l + bl) | 0;
    h[2] = (h1h + bh + (h1l >>> 0 < bl >>> 0 ? 1 : 0)) | 0;
    h2l = h[5] = (h2l + cl) | 0;
    h[4] = (h2h + ch + (h2l >>> 0 < cl >>> 0 ? 1 : 0)) | 0;
    h3l = h[7] = (h3l + dl) | 0;
    h[6] = (h3h + dh + (h3l >>> 0 < dl >>> 0 ? 1 : 0)) | 0;
    h4l = h[9] = (h4l + el) | 0;
    h[8] = (h4h + eh + (h4l >>> 0 < el >>> 0 ? 1 : 0)) | 0;
    h5l = h[11] = (h5l + fl) | 0;
    h[10] = (h5h + fh + (h5l >>> 0 < fl >>> 0 ? 1 : 0)) | 0;
    h6l = h[13] = (h6l + gl) | 0;
    h[12] = (h6h + gh + (h6l >>> 0 < gl >>> 0 ? 1 : 0)) | 0;
    h7l = h[15] = (h7l + hl) | 0;
    h[14] = (h7h + hh + (h7l >>> 0 < hl >>> 0 ? 1 : 0)) | 0;
  }
};
sjcl.hash.sha1 = function(hash) {
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};
sjcl.hash.sha1.hash = function(data) {
  return new sjcl.hash.sha1().update(data).finalize();
};
sjcl.hash.sha1.prototype = {
  blockSize: 512,
  reset: function() {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  update: function(data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i,
      b = (this._buffer = sjcl.bitArray.concat(this._buffer, data)),
      ol = this._length,
      nl = (this._length = ol + sjcl.bitArray.bitLength(data));
    for (
      i = (this.blockSize + ol) & -this.blockSize;
      i <= nl;
      i += this.blockSize
    ) {
      this._block(b.splice(0, 16));
    }
    return this;
  },
  finalize: function() {
    var i,
      b = this._buffer,
      h = this._h;
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);
    while (b.length) {
      this._block(b.splice(0, 16));
    }
    this.reset();
    return h;
  },
  _init: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
  _key: [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6],
  _f: function(t, b, c, d) {
    if (t <= 19) {
      return (b & c) | (~b & d);
    } else if (t <= 39) {
      return b ^ c ^ d;
    } else if (t <= 59) {
      return (b & c) | (b & d) | (c & d);
    } else if (t <= 79) {
      return b ^ c ^ d;
    }
  },
  _S: function(n, x) {
    return (x << n) | (x >>> (32 - n));
  },
  _block: function(words) {
    var t,
      tmp,
      a,
      b,
      c,
      d,
      e,
      w = words.slice(0),
      h = this._h,
      k = this._key;
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];
    for (t = 0; t <= 79; t++) {
      if (t >= 16) {
        w[t] = this._S(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
      }
      tmp =
        (this._S(5, a) +
          this._f(t, b, c, d) +
          e +
          w[t] +
          this._key[Math.floor(t / 20)]) |
        0;
      e = d;
      d = c;
      c = this._S(30, b);
      b = a;
      a = tmp;
    }
    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
  }
};
sjcl.mode.ccm = {
  name: "ccm",
  encrypt: function(prf, plaintext, iv, adata, tlen) {
    var L,
      i,
      out = plaintext.slice(0),
      tag,
      w = sjcl.bitArray,
      ivl = w.bitLength(iv) / 8,
      ol = w.bitLength(out) / 8;
    tlen = tlen || 64;
    adata = adata || [];
    if (ivl < 7) {
      throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
    }
    for (L = 2; L < 4 && ol >>> (8 * L); L++) {}
    if (L < 15 - ivl) {
      L = 15 - ivl;
    }
    iv = w.clamp(iv, 8 * (15 - L));
    tag = sjcl.mode.ccm._computeTag(prf, plaintext, iv, adata, tlen, L);
    out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
    return w.concat(out.data, out.tag);
  },
  decrypt: function(prf, ciphertext, iv, adata, tlen) {
    tlen = tlen || 64;
    adata = adata || [];
    var L,
      i,
      w = sjcl.bitArray,
      ivl = w.bitLength(iv) / 8,
      ol = w.bitLength(ciphertext),
      out = w.clamp(ciphertext, ol - tlen),
      tag = w.bitSlice(ciphertext, ol - tlen),
      tag2;
    ol = (ol - tlen) / 8;
    if (ivl < 7) {
      throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
    }
    for (L = 2; L < 4 && ol >>> (8 * L); L++) {}
    if (L < 15 - ivl) {
      L = 15 - ivl;
    }
    iv = w.clamp(iv, 8 * (15 - L));
    out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
    tag2 = sjcl.mode.ccm._computeTag(prf, out.data, iv, adata, tlen, L);
    if (!w.equal(out.tag, tag2)) {
      throw new sjcl.exception.corrupt("ccm: tag doesn't match");
    }
    return out.data;
  },
  _computeTag: function(prf, plaintext, iv, adata, tlen, L) {
    var q,
      mac,
      field = 0,
      offset = 24,
      tmp,
      i,
      macData = [],
      w = sjcl.bitArray,
      xor = w._xor4;
    tlen /= 8;
    if (tlen % 2 || tlen < 4 || tlen > 16) {
      throw new sjcl.exception.invalid("ccm: invalid tag length");
    }
    if (adata.length > 0xffffffff || plaintext.length > 0xffffffff) {
      throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");
    }
    mac = [
      w.partial(8, (adata.length ? 1 << 6 : 0) | ((tlen - 2) << 2) | (L - 1))
    ];
    mac = w.concat(mac, iv);
    mac[3] |= w.bitLength(plaintext) / 8;
    mac = prf.encrypt(mac);
    if (adata.length) {
      tmp = w.bitLength(adata) / 8;
      if (tmp <= 0xfeff) {
        macData = [w.partial(16, tmp)];
      } else if (tmp <= 0xffffffff) {
        macData = w.concat([w.partial(16, 0xfffe)], [tmp]);
      }
      macData = w.concat(macData, adata);
      for (i = 0; i < macData.length; i += 4) {
        mac = prf.encrypt(xor(mac, macData.slice(i, i + 4).concat([0, 0, 0])));
      }
    }
    for (i = 0; i < plaintext.length; i += 4) {
      mac = prf.encrypt(xor(mac, plaintext.slice(i, i + 4).concat([0, 0, 0])));
    }
    return w.clamp(mac, tlen * 8);
  },
  _ctrMode: function(prf, data, iv, tag, tlen, L) {
    var enc,
      i,
      w = sjcl.bitArray,
      xor = w._xor4,
      ctr,
      b,
      l = data.length,
      bl = w.bitLength(data);
    ctr = w
      .concat([w.partial(8, L - 1)], iv)
      .concat([0, 0, 0])
      .slice(0, 4);
    tag = w.bitSlice(xor(tag, prf.encrypt(ctr)), 0, tlen);
    if (!l) {
      return { tag: tag, data: [] };
    }
    for (i = 0; i < l; i += 4) {
      ctr[3]++;
      enc = prf.encrypt(ctr);
      data[i] ^= enc[0];
      data[i + 1] ^= enc[1];
      data[i + 2] ^= enc[2];
      data[i + 3] ^= enc[3];
    }
    return { tag: tag, data: w.clamp(data, bl) };
  }
};
sjcl.misc.hmac = function(key, Hash) {
  this._hash = Hash = Hash || sjcl.hash.sha256;
  var exKey = [[], []],
    i,
    bs = Hash.prototype.blockSize / 32;
  this._baseHash = [new Hash(), new Hash()];
  if (key.length > bs) {
    key = Hash.hash(key);
  }
  for (i = 0; i < bs; i++) {
    exKey[0][i] = key[i] ^ 0x36363636;
    exKey[1][i] = key[i] ^ 0x5c5c5c5c;
  }
  this._baseHash[0].update(exKey[0]);
  this._baseHash[1].update(exKey[1]);
};
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function(
  data
) {
  var w = new this._hash(this._baseHash[0]).update(data).finalize();
  return new this._hash(this._baseHash[1]).update(w).finalize();
};
sjcl.misc.pbkdf2 = function(password, salt, count, length, Prff) {
  count = count || 1000;
  if (length < 0 || count < 0) {
    throw sjcl.exception.invalid("invalid params to pbkdf2");
  }
  if (typeof password === "string") {
    password = sjcl.codec.utf8String.toBits(password);
  }
  Prff = Prff || sjcl.misc.hmac;
  var prf = new Prff(password),
    u,
    ui,
    i,
    j,
    k,
    out = [],
    b = sjcl.bitArray;
  for (k = 1; 32 * out.length < (length || 1); k++) {
    u = ui = prf.encrypt(b.concat(salt, [k]));
    for (i = 1; i < count; i++) {
      ui = prf.encrypt(ui);
      for (j = 0; j < ui.length; j++) {
        u[j] ^= ui[j];
      }
    }
    out = out.concat(u);
  }
  if (length) {
    out = b.clamp(out, length);
  }
  return out;
};
sjcl.prng = function(defaultParanoia) {
  this._pools = [new sjcl.hash.sha256()];
  this._poolEntropy = [0];
  this._reseedCount = 0;
  this._robins = {};
  this._eventId = 0;
  this._collectorIds = {};
  this._collectorIdNext = 0;
  this._strength = 0;
  this._poolStrength = 0;
  this._nextReseed = 0;
  this._key = [0, 0, 0, 0, 0, 0, 0, 0];
  this._counter = [0, 0, 0, 0];
  this._cipher = undefined;
  this._defaultParanoia = defaultParanoia;
  this._collectorsStarted = false;
  this._callbacks = { progress: {}, seeded: {} };
  this._callbackI = 0;
  this._NOT_READY = 0;
  this._READY = 1;
  this._REQUIRES_RESEED = 2;
  this._MAX_WORDS_PER_BURST = 65536;
  this._PARANOIA_LEVELS = [0, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024];
  this._MILLISECONDS_PER_RESEED = 30000;
  this._BITS_PER_RESEED = 80;
};
sjcl.prng.prototype = {
  randomWords: function(nwords, paranoia) {
    var out = [],
      i,
      readiness = this.isReady(paranoia),
      g;
    if (readiness === this._NOT_READY) {
      throw new sjcl.exception.notReady("generator isn't seeded");
    } else if (readiness & this._REQUIRES_RESEED) {
      this._reseedFromPools(!(readiness & this._READY));
    }
    for (i = 0; i < nwords; i += 4) {
      if ((i + 1) % this._MAX_WORDS_PER_BURST === 0) {
        this._gate();
      }
      g = this._gen4words();
      out.push(g[0], g[1], g[2], g[3]);
    }
    this._gate();
    return out.slice(0, nwords);
  },
  setDefaultParanoia: function(paranoia) {
    this._defaultParanoia = paranoia;
  },
  addEntropy: function(data, estimatedEntropy, source) {
    source = source || "user";
    var id,
      i,
      tmp,
      t = new Date().valueOf(),
      robin = this._robins[source],
      oldReady = this.isReady(),
      err = 0;
    id = this._collectorIds[source];
    if (id === undefined) {
      id = this._collectorIds[source] = this._collectorIdNext++;
    }
    if (robin === undefined) {
      robin = this._robins[source] = 0;
    }
    this._robins[source] = (this._robins[source] + 1) % this._pools.length;
    switch (typeof data) {
      case "number":
        if (estimatedEntropy === undefined) {
          estimatedEntropy = 1;
        }
        this._pools[robin].update([
          id,
          this._eventId++,
          1,
          estimatedEntropy,
          t,
          1,
          data | 0
        ]);
        break;
      case "object":
        var objName = Object.prototype.toString.call(data);
        if (objName === "[object Uint32Array]") {
          tmp = [];
          for (i = 0; i < data.length; i++) {
            tmp.push(data[i]);
          }
          data = tmp;
        } else {
          if (objName !== "[object Array]") {
            err = 1;
          }
          for (i = 0; i < data.length && !err; i++) {
            if (typeof data[i] != "number") {
              err = 1;
            }
          }
        }
        if (!err) {
          if (estimatedEntropy === undefined) {
            estimatedEntropy = 0;
            for (i = 0; i < data.length; i++) {
              tmp = data[i];
              while (tmp > 0) {
                estimatedEntropy++;
                tmp = tmp >>> 1;
              }
            }
          }
          this._pools[robin].update(
            [id, this._eventId++, 2, estimatedEntropy, t, data.length].concat(
              data
            )
          );
        }
        break;
      case "string":
        if (estimatedEntropy === undefined) {
          estimatedEntropy = data.length;
        }
        this._pools[robin].update([
          id,
          this._eventId++,
          3,
          estimatedEntropy,
          t,
          data.length
        ]);
        this._pools[robin].update(data);
        break;
      default:
        err = 1;
    }
    if (err) {
      throw new sjcl.exception.bug(
        "random: addEntropy only supports number, array of numbers or string"
      );
    }
    this._poolEntropy[robin] += estimatedEntropy;
    this._poolStrength += estimatedEntropy;
    if (oldReady === this._NOT_READY) {
      if (this.isReady() !== this._NOT_READY) {
        this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
      }
      this._fireEvent("progress", this.getProgress());
    }
  },
  isReady: function(paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[
      paranoia !== undefined ? paranoia : this._defaultParanoia
    ];
    if (this._strength && this._strength >= entropyRequired) {
      return this._poolEntropy[0] > this._BITS_PER_RESEED &&
        new Date().valueOf() > this._nextReseed
        ? this._REQUIRES_RESEED | this._READY
        : this._READY;
    } else {
      return this._poolStrength >= entropyRequired
        ? this._REQUIRES_RESEED | this._NOT_READY
        : this._NOT_READY;
    }
  },
  getProgress: function(paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[
      paranoia ? paranoia : this._defaultParanoia
    ];
    if (this._strength >= entropyRequired) {
      return 1.0;
    } else {
      return this._poolStrength > entropyRequired
        ? 1.0
        : this._poolStrength / entropyRequired;
    }
  },
  startCollectors: function() {
    if (this._collectorsStarted) {
      return;
    }
    if (window.addEventListener) {
      window.addEventListener("load", this._loadTimeCollector, false);
      window.addEventListener("mousemove", this._mouseCollector, false);
    } else if (document.attachEvent) {
      document.attachEvent("onload", this._loadTimeCollector);
      document.attachEvent("onmousemove", this._mouseCollector);
    } else {
      throw new sjcl.exception.bug("can't attach event");
    }
    this._collectorsStarted = true;
  },
  stopCollectors: function() {
    if (!this._collectorsStarted) {
      return;
    }
    if (window.removeEventListener) {
      window.removeEventListener("load", this._loadTimeCollector, false);
      window.removeEventListener("mousemove", this._mouseCollector, false);
    } else if (window.detachEvent) {
      window.detachEvent("onload", this._loadTimeCollector);
      window.detachEvent("onmousemove", this._mouseCollector);
    }
    this._collectorsStarted = false;
  },
  addEventListener: function(name, callback) {
    this._callbacks[name][this._callbackI++] = callback;
  },
  removeEventListener: function(name, cb) {
    var i,
      j,
      cbs = this._callbacks[name],
      jsTemp = [];
    for (j in cbs) {
      if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
        jsTemp.push(j);
      }
    }
    for (i = 0; i < jsTemp.length; i++) {
      j = jsTemp[i];
      delete cbs[j];
    }
  },
  _gen4words: function() {
    for (var i = 0; i < 4; i++) {
      this._counter[i] = (this._counter[i] + 1) | 0;
      if (this._counter[i]) {
        break;
      }
    }
    return this._cipher.encrypt(this._counter);
  },
  _gate: function() {
    this._key = this._gen4words().concat(this._gen4words());
    this._cipher = new sjcl.cipher.aes(this._key);
  },
  _reseed: function(seedWords) {
    this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
    this._cipher = new sjcl.cipher.aes(this._key);
    for (var i = 0; i < 4; i++) {
      this._counter[i] = (this._counter[i] + 1) | 0;
      if (this._counter[i]) {
        break;
      }
    }
  },
  _reseedFromPools: function(full) {
    var reseedData = [],
      strength = 0,
      i;
    this._nextReseed = reseedData[0] =
      new Date().valueOf() + this._MILLISECONDS_PER_RESEED;
    for (i = 0; i < 16; i++) {
      reseedData.push((Math.random() * 0x100000000) | 0);
    }
    for (i = 0; i < this._pools.length; i++) {
      reseedData = reseedData.concat(this._pools[i].finalize());
      strength += this._poolEntropy[i];
      this._poolEntropy[i] = 0;
      if (!full && this._reseedCount & (1 << i)) {
        break;
      }
    }
    if (this._reseedCount >= 1 << this._pools.length) {
      this._pools.push(new sjcl.hash.sha256());
      this._poolEntropy.push(0);
    }
    this._poolStrength -= strength;
    if (strength > this._strength) {
      this._strength = strength;
    }
    this._reseedCount++;
    this._reseed(reseedData);
  },
  _mouseCollector: function(ev) {
    var x = ev.x || ev.clientX || ev.offsetX || 0,
      y = ev.y || ev.clientY || ev.offsetY || 0;
    sjcl.random.addEntropy([x, y], 2, "mouse");
  },
  _loadTimeCollector: function(ev) {
    sjcl.random.addEntropy(new Date().valueOf(), 2, "loadtime");
  },
  _fireEvent: function(name, arg) {
    var j,
      cbs = sjcl.random._callbacks[name],
      cbsTemp = [];
    for (j in cbs) {
      if (cbs.hasOwnProperty(j)) {
        cbsTemp.push(cbs[j]);
      }
    }
    for (j = 0; j < cbsTemp.length; j++) {
      cbsTemp[j](arg);
    }
  }
};
sjcl.random = new sjcl.prng(6);
(function() {
  try {
    var ab = new Uint32Array(32);
    crypto.getRandomValues(ab);
    sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
  } catch (e) {}
})();
sjcl.json = {
  defaults: {
    v: 1,
    iter: 1000,
    ks: 128,
    ts: 64,
    mode: "ccm",
    adata: "",
    cipher: "aes"
  },
  encrypt: function(password, plaintext, params, rp) {
    params = params || {};
    rp = rp || {};
    var j = sjcl.json,
      p = j._add({ iv: sjcl.random.randomWords(4, 0) }, j.defaults),
      tmp,
      prp,
      adata;
    j._add(p, params);
    adata = p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }
    if (
      !sjcl.mode[p.mode] ||
      !sjcl.cipher[p.cipher] ||
      (typeof password === "string" && p.iter <= 100) ||
      (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
      (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
      (p.iv.length < 2 || p.iv.length > 4)
    ) {
      throw new sjcl.exception.invalid("json encrypt: invalid parameters");
    }
    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0, p.ks / 32);
      p.salt = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.publicKey) {
      tmp = password.kem();
      p.kemtag = tmp.tag;
      password = tmp.key.slice(0, p.ks / 32);
    }
    if (typeof plaintext === "string") {
      plaintext = sjcl.codec.utf8String.toBits(plaintext);
    }
    if (typeof adata === "string") {
      adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);
    j._add(rp, p);
    rp.key = password;
    p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, adata, p.ts);
    return j.encode(p);
  },
  decrypt: function(password, ciphertext, params, rp) {
    params = params || {};
    rp = rp || {};
    var j = sjcl.json,
      p = j._add(
        j._add(j._add({}, j.defaults), j.decode(ciphertext)),
        params,
        true
      ),
      ct,
      tmp,
      prp,
      adata = p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }
    if (
      !sjcl.mode[p.mode] ||
      !sjcl.cipher[p.cipher] ||
      (typeof password === "string" && p.iter <= 100) ||
      (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
      (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
      !p.iv ||
      (p.iv.length < 2 || p.iv.length > 4)
    ) {
      throw new sjcl.exception.invalid("json decrypt: invalid parameters");
    }
    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0, p.ks / 32);
      p.salt = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.secretKey) {
      password = password
        .unkem(sjcl.codec.base64.toBits(p.kemtag))
        .slice(0, p.ks / 32);
    }
    if (typeof adata === "string") {
      adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);
    ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, adata, p.ts);
    j._add(rp, p);
    rp.key = password;
    return sjcl.codec.utf8String.fromBits(ct);
  },
  encode: function(obj) {
    var i,
      out = "{",
      comma = "";
    for (i in obj) {
      if (obj.hasOwnProperty(i)) {
        if (!i.match(/^[a-z0-9]+$/i)) {
          throw new sjcl.exception.invalid(
            "json encode: invalid property name"
          );
        }
        out += comma + '"' + i + '":';
        comma = ",";
        switch (typeof obj[i]) {
          case "number":
          case "boolean":
            out += obj[i];
            break;
          case "string":
            out += '"' + escape(obj[i]) + '"';
            break;
          case "object":
            out += '"' + sjcl.codec.base64.fromBits(obj[i], 0) + '"';
            break;
          default:
            throw new sjcl.exception.bug("json encode: unsupported type");
        }
      }
    }
    return out + "}";
  },
  decode: function(str) {
    str = str.replace(/\s/g, "");
    if (!str.match(/^\{.*\}$/)) {
      throw new sjcl.exception.invalid("json decode: this isn't json!");
    }
    var a = str.replace(/^\{|\}$/g, "").split(/,/),
      out = {},
      i,
      m;
    for (i = 0; i < a.length; i++) {
      if (
        !(m = a[i].match(
          /^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i
        ))
      ) {
        throw new sjcl.exception.invalid("json decode: this isn't json!");
      }
      if (m[3]) {
        out[m[2]] = parseInt(m[3], 10);
      } else {
        out[m[2]] = m[2].match(/^(ct|salt|iv)$/)
          ? sjcl.codec.base64.toBits(m[4])
          : unescape(m[4]);
      }
    }
    return out;
  },
  _add: function(target, src, requireSame) {
    if (target === undefined) {
      target = {};
    }
    if (src === undefined) {
      return target;
    }
    var i;
    for (i in src) {
      if (src.hasOwnProperty(i)) {
        if (requireSame && target[i] !== undefined && target[i] !== src[i]) {
          throw new sjcl.exception.invalid("required parameter overridden");
        }
        target[i] = src[i];
      }
    }
    return target;
  },
  _subtract: function(plus, minus) {
    var out = {},
      i;
    for (i in plus) {
      if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
        out[i] = plus[i];
      }
    }
    return out;
  },
  _filter: function(src, filter) {
    var out = {},
      i;
    for (i = 0; i < filter.length; i++) {
      if (src[filter[i]] !== undefined) {
        out[filter[i]] = src[filter[i]];
      }
    }
    return out;
  }
};
sjcl.encrypt = sjcl.json.encrypt;
sjcl.decrypt = sjcl.json.decrypt;
sjcl.misc._pbkdf2Cache = {};
sjcl.misc.cachedPbkdf2 = function(password, obj) {
  var cache = sjcl.misc._pbkdf2Cache,
    c,
    cp,
    str,
    salt,
    iter;
  obj = obj || {};
  iter = obj.iter || 1000;
  cp = cache[password] = cache[password] || {};
  c = cp[iter] = cp[iter] || {
    firstSalt:
      obj.salt && obj.salt.length
        ? obj.salt.slice(0)
        : sjcl.random.randomWords(2, 0)
  };
  salt = obj.salt === undefined ? c.firstSalt : obj.salt;
  c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
  return { key: c[salt].slice(0), salt: salt.slice(0) };
};
sjcl.bn = function(it) {
  this.initWith(it);
};
sjcl.bn.prototype = {
  radix: 24,
  maxMul: 8,
  _class: sjcl.bn,
  copy: function() {
    return new this._class(this);
  },
  initWith: function(it) {
    var i = 0,
      k,
      n,
      l;
    switch (typeof it) {
      case "object":
        this.limbs = it.limbs.slice(0);
        break;
      case "number":
        this.limbs = [it];
        this.normalize();
        break;
      case "string":
        it = it.replace(/^0x/, "");
        this.limbs = [];
        k = this.radix / 4;
        for (i = 0; i < it.length; i += k) {
          this.limbs.push(
            parseInt(
              it.substring(Math.max(it.length - i - k, 0), it.length - i),
              16
            )
          );
        }
        break;
      default:
        this.limbs = [0];
    }
    return this;
  },
  equals: function(that) {
    if (typeof that === "number") {
      that = new this._class(that);
    }
    var difference = 0,
      i;
    this.fullReduce();
    that.fullReduce();
    for (i = 0; i < this.limbs.length || i < that.limbs.length; i++) {
      difference |= this.getLimb(i) ^ that.getLimb(i);
    }
    return difference === 0;
  },
  getLimb: function(i) {
    return i >= this.limbs.length ? 0 : this.limbs[i];
  },
  greaterEquals: function(that) {
    if (typeof that === "number") {
      that = new this._class(that);
    }
    var less = 0,
      greater = 0,
      i,
      a,
      b;
    i = Math.max(this.limbs.length, that.limbs.length) - 1;
    for (; i >= 0; i--) {
      a = this.getLimb(i);
      b = that.getLimb(i);
      greater |= (b - a) & ~less;
      less |= (a - b) & ~greater;
    }
    return (greater | ~less) >>> 31;
  },
  toString: function() {
    this.fullReduce();
    var out = "",
      i,
      s,
      l = this.limbs;
    for (i = 0; i < this.limbs.length; i++) {
      s = l[i].toString(16);
      while (i < this.limbs.length - 1 && s.length < 6) {
        s = "0" + s;
      }
      out = s + out;
    }
    return "0x" + out;
  },
  addM: function(that) {
    if (typeof that !== "object") {
      that = new this._class(that);
    }
    var i,
      l = this.limbs,
      ll = that.limbs;
    for (i = l.length; i < ll.length; i++) {
      l[i] = 0;
    }
    for (i = 0; i < ll.length; i++) {
      l[i] += ll[i];
    }
    return this;
  },
  doubleM: function() {
    var i,
      carry = 0,
      tmp,
      r = this.radix,
      m = this.radixMask,
      l = this.limbs;
    for (i = 0; i < l.length; i++) {
      tmp = l[i];
      tmp = tmp + tmp + carry;
      l[i] = tmp & m;
      carry = tmp >> r;
    }
    if (carry) {
      l.push(carry);
    }
    return this;
  },
  halveM: function() {
    var i,
      carry = 0,
      tmp,
      r = this.radix,
      l = this.limbs;
    for (i = l.length - 1; i >= 0; i--) {
      tmp = l[i];
      l[i] = (tmp + carry) >> 1;
      carry = (tmp & 1) << r;
    }
    if (!l[l.length - 1]) {
      l.pop();
    }
    return this;
  },
  subM: function(that) {
    if (typeof that !== "object") {
      that = new this._class(that);
    }
    var i,
      l = this.limbs,
      ll = that.limbs;
    for (i = l.length; i < ll.length; i++) {
      l[i] = 0;
    }
    for (i = 0; i < ll.length; i++) {
      l[i] -= ll[i];
    }
    return this;
  },
  mod: function(that) {
    var neg = !this.greaterEquals(new sjcl.bn(0));
    that = new sjcl.bn(that).normalize();
    var out = new sjcl.bn(this).normalize(),
      ci = 0;
    if (neg) out = new sjcl.bn(0).subM(out).normalize();
    for (; out.greaterEquals(that); ci++) {
      that.doubleM();
    }
    if (neg) out = that.sub(out).normalize();
    for (; ci > 0; ci--) {
      that.halveM();
      if (out.greaterEquals(that)) {
        out.subM(that).normalize();
      }
    }
    return out.trim();
  },
  inverseMod: function(p) {
    var a = new sjcl.bn(1),
      b = new sjcl.bn(0),
      x = new sjcl.bn(this),
      y = new sjcl.bn(p),
      tmp,
      i,
      nz = 1;
    do {
      if (x.limbs[0] & 1) {
        if (!x.greaterEquals(y)) {
          tmp = x;
          x = y;
          y = tmp;
          tmp = a;
          a = b;
          b = tmp;
        }
        x.subM(y);
        x.normalize();
        if (!a.greaterEquals(b)) {
          a.addM(p);
        }
        a.subM(b);
      }
      x.halveM();
      if (a.limbs[0] & 1) {
        a.addM(p);
      }
      a.normalize();
      a.halveM();
      for (i = nz = 0; i < x.limbs.length; i++) {
        nz |= x.limbs[i];
      }
    } while (nz);
    if (!y.equals(1)) {
      throw new sjcl.exception.invalid(
        "inverseMod: p and x must be relatively prime"
      );
    }
    return b;
  },
  add: function(that) {
    return this.copy().addM(that);
  },
  sub: function(that) {
    return this.copy().subM(that);
  },
  mul: function(that) {
    if (typeof that === "number") {
      that = new this._class(that);
    }
    var i,
      j,
      a = this.limbs,
      b = that.limbs,
      al = a.length,
      bl = b.length,
      out = new this._class(),
      c = out.limbs,
      ai,
      ii = this.maxMul;
    for (i = 0; i < this.limbs.length + that.limbs.length + 1; i++) {
      c[i] = 0;
    }
    for (i = 0; i < al; i++) {
      ai = a[i];
      for (j = 0; j < bl; j++) {
        c[i + j] += ai * b[j];
      }
      if (!--ii) {
        ii = this.maxMul;
        out.cnormalize();
      }
    }
    return out.cnormalize().reduce();
  },
  square: function() {
    return this.mul(this);
  },
  power: function(l) {
    if (typeof l === "number") {
      l = [l];
    } else if (l.limbs !== undefined) {
      l = l.normalize().limbs;
    }
    var i,
      j,
      out = new this._class(1),
      pow = this;
    for (i = 0; i < l.length; i++) {
      for (j = 0; j < this.radix; j++) {
        if (l[i] & (1 << j)) {
          out = out.mul(pow);
        }
        pow = pow.square();
      }
    }
    return out;
  },
  mulmod: function(that, N) {
    return this.mod(N)
      .mul(that.mod(N))
      .mod(N);
  },
  powermod: function(x, N) {
    var result = new sjcl.bn(1),
      a = new sjcl.bn(this),
      k = new sjcl.bn(x);
    while (true) {
      if (k.limbs[0] & 1) {
        result = result.mulmod(a, N);
      }
      k.halveM();
      if (k.equals(0)) {
        break;
      }
      a = a.mulmod(a, N);
    }
    return result.normalize().reduce();
  },
  trim: function() {
    var l = this.limbs,
      p;
    do {
      p = l.pop();
    } while (l.length && p === 0);
    l.push(p);
    return this;
  },
  reduce: function() {
    return this;
  },
  fullReduce: function() {
    return this.normalize();
  },
  normalize: function() {
    var carry = 0,
      i,
      pv = this.placeVal,
      ipv = this.ipv,
      l,
      m,
      limbs = this.limbs,
      ll = limbs.length,
      mask = this.radixMask;
    for (i = 0; i < ll || (carry !== 0 && carry !== -1); i++) {
      l = (limbs[i] || 0) + carry;
      m = limbs[i] = l & mask;
      carry = (l - m) * ipv;
    }
    if (carry === -1) {
      limbs[i - 1] -= this.placeVal;
    }
    return this;
  },
  cnormalize: function() {
    var carry = 0,
      i,
      ipv = this.ipv,
      l,
      m,
      limbs = this.limbs,
      ll = limbs.length,
      mask = this.radixMask;
    for (i = 0; i < ll - 1; i++) {
      l = limbs[i] + carry;
      m = limbs[i] = l & mask;
      carry = (l - m) * ipv;
    }
    limbs[i] += carry;
    return this;
  },
  toBits: function(len) {
    this.fullReduce();
    len = len || this.exponent || this.bitLength();
    var i = Math.floor((len - 1) / 24),
      w = sjcl.bitArray,
      e = ((len + 7) & -8) % this.radix || this.radix,
      out = [w.partial(e, this.getLimb(i))];
    for (i--; i >= 0; i--) {
      out = w.concat(out, [
        w.partial(Math.min(this.radix, len), this.getLimb(i))
      ]);
      len -= this.radix;
    }
    return out;
  },
  bitLength: function() {
    this.fullReduce();
    var out = this.radix * (this.limbs.length - 1),
      b = this.limbs[this.limbs.length - 1];
    for (; b; b >>>= 1) {
      out++;
    }
    return (out + 7) & -8;
  }
};
sjcl.bn.fromBits = function(bits) {
  var Class = this,
    out = new Class(),
    words = [],
    w = sjcl.bitArray,
    t = this.prototype,
    l = Math.min(this.bitLength || 0x100000000, w.bitLength(bits)),
    e = l % t.radix || t.radix;
  words[0] = w.extract(bits, 0, e);
  for (; e < l; e += t.radix) {
    words.unshift(w.extract(bits, e, t.radix));
  }
  out.limbs = words;
  return out;
};
sjcl.bn.prototype.ipv =
  1 / (sjcl.bn.prototype.placeVal = Math.pow(2, sjcl.bn.prototype.radix));
sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;
sjcl.bn.pseudoMersennePrime = function(exponent, coeff) {
  function p(it) {
    this.initWith(it);
  }
  var ppr = (p.prototype = new sjcl.bn()),
    i,
    tmp,
    mo;
  mo = ppr.modOffset = Math.ceil((tmp = exponent / ppr.radix));
  ppr.exponent = exponent;
  ppr.offset = [];
  ppr.factor = [];
  ppr.minOffset = mo;
  ppr.fullMask = 0;
  ppr.fullOffset = [];
  ppr.fullFactor = [];
  ppr.modulus = p.modulus = new sjcl.bn(Math.pow(2, exponent));
  ppr.fullMask = 0 | -Math.pow(2, exponent % ppr.radix);
  for (i = 0; i < coeff.length; i++) {
    ppr.offset[i] = Math.floor(coeff[i][0] / ppr.radix - tmp);
    ppr.fullOffset[i] = Math.ceil(coeff[i][0] / ppr.radix - tmp);
    ppr.factor[i] =
      coeff[i][1] *
      Math.pow(1 / 2, exponent - coeff[i][0] + ppr.offset[i] * ppr.radix);
    ppr.fullFactor[i] =
      coeff[i][1] *
      Math.pow(1 / 2, exponent - coeff[i][0] + ppr.fullOffset[i] * ppr.radix);
    ppr.modulus.addM(new sjcl.bn(Math.pow(2, coeff[i][0]) * coeff[i][1]));
    ppr.minOffset = Math.min(ppr.minOffset, -ppr.offset[i]);
  }
  ppr._class = p;
  ppr.modulus.cnormalize();
  ppr.reduce = function() {
    var i,
      k,
      l,
      mo = this.modOffset,
      limbs = this.limbs,
      aff,
      off = this.offset,
      ol = this.offset.length,
      fac = this.factor,
      ll;
    i = this.minOffset;
    while (limbs.length > mo) {
      l = limbs.pop();
      ll = limbs.length;
      for (k = 0; k < ol; k++) {
        limbs[ll + off[k]] -= fac[k] * l;
      }
      i--;
      if (!i) {
        limbs.push(0);
        this.cnormalize();
        i = this.minOffset;
      }
    }
    this.cnormalize();
    return this;
  };
  ppr._strongReduce =
    ppr.fullMask === -1
      ? ppr.reduce
      : function() {
          var limbs = this.limbs,
            i = limbs.length - 1,
            k,
            l;
          this.reduce();
          if (i === this.modOffset - 1) {
            l = limbs[i] & this.fullMask;
            limbs[i] -= l;
            for (k = 0; k < this.fullOffset.length; k++) {
              limbs[i + this.fullOffset[k]] -= this.fullFactor[k] * l;
            }
            this.normalize();
          }
        };
  ppr.fullReduce = function() {
    var greater, i;
    this._strongReduce();
    this.addM(this.modulus);
    this.addM(this.modulus);
    this.normalize();
    this._strongReduce();
    for (i = this.limbs.length; i < this.modOffset; i++) {
      this.limbs[i] = 0;
    }
    greater = this.greaterEquals(this.modulus);
    for (i = 0; i < this.limbs.length; i++) {
      this.limbs[i] -= this.modulus.limbs[i] * greater;
    }
    this.cnormalize();
    return this;
  };
  ppr.inverse = function() {
    return this.power(this.modulus.sub(2));
  };
  p.fromBits = sjcl.bn.fromBits;
  return p;
};
sjcl.bn.prime = {
  p127: sjcl.bn.pseudoMersennePrime(127, [[0, -1]]),
  p25519: sjcl.bn.pseudoMersennePrime(255, [[0, -19]]),
  p192: sjcl.bn.pseudoMersennePrime(192, [[0, -1], [64, -1]]),
  p224: sjcl.bn.pseudoMersennePrime(224, [[0, 1], [96, -1]]),
  p256: sjcl.bn.pseudoMersennePrime(256, [
    [0, -1],
    [96, 1],
    [192, 1],
    [224, -1]
  ]),
  p384: sjcl.bn.pseudoMersennePrime(384, [
    [0, -1],
    [32, 1],
    [96, -1],
    [128, -1]
  ]),
  p521: sjcl.bn.pseudoMersennePrime(521, [[0, -1]])
};
sjcl.bn.random = function(modulus, paranoia) {
  if (typeof modulus !== "object") {
    modulus = new sjcl.bn(modulus);
  }
  var words,
    i,
    l = modulus.limbs.length,
    m = modulus.limbs[l - 1] + 1,
    out = new sjcl.bn();
  while (true) {
    do {
      words = sjcl.random.randomWords(l, paranoia);
      if (words[l - 1] < 0) {
        words[l - 1] += 0x100000000;
      }
    } while (Math.floor(words[l - 1] / m) === Math.floor(0x100000000 / m));
    words[l - 1] %= m;
    for (i = 0; i < l - 1; i++) {
      words[i] &= modulus.radixMask;
    }
    out.limbs = words;
    if (!out.greaterEquals(modulus)) {
      return out;
    }
  }
};
sjcl.ecc = {};
sjcl.ecc.point = function(curve, x, y) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    if (x instanceof sjcl.bn) {
      x = new curve.field(x);
    }
    if (y instanceof sjcl.bn) {
      y = new curve.field(y);
    }
    this.x = x;
    this.y = y;
    this.isIdentity = false;
  }
  this.curve = curve;
};
sjcl.ecc.point.prototype = {
  toJac: function() {
    return new sjcl.ecc.pointJac(
      this.curve,
      this.x,
      this.y,
      new this.curve.field(1)
    );
  },
  mult: function(k) {
    return this.toJac()
      .mult(k, this)
      .toAffine();
  },
  mult2: function(k, k2, affine2) {
    return this.toJac()
      .mult2(k, this, k2, affine2)
      .toAffine();
  },
  multiples: function() {
    var m, i, j;
    if (this._multiples === undefined) {
      j = this.toJac().doubl();
      m = this._multiples = [
        new sjcl.ecc.point(this.curve),
        this,
        j.toAffine()
      ];
      for (i = 3; i < 16; i++) {
        j = j.add(this);
        m.push(j.toAffine());
      }
    }
    return this._multiples;
  },
  isValid: function() {
    return this.y
      .square()
      .equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
  },
  toBits: function() {
    return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
  }
};
sjcl.ecc.pointJac = function(curve, x, y, z) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.z = z;
    this.isIdentity = false;
  }
  this.curve = curve;
};
sjcl.ecc.pointJac.prototype = {
  add: function(T) {
    var S = this,
      sz2,
      c,
      d,
      c2,
      x1,
      x2,
      x,
      y1,
      y2,
      y,
      z;
    if (S.curve !== T.curve) {
      throw "sjcl.ecc.add(): Points must be on the same curve to add them!";
    }
    if (S.isIdentity) {
      return T.toJac();
    } else if (T.isIdentity) {
      return S;
    }
    sz2 = S.z.square();
    c = T.x.mul(sz2).subM(S.x);
    if (c.equals(0)) {
      if (S.y.equals(T.y.mul(sz2.mul(S.z)))) {
        return S.doubl();
      } else {
        return new sjcl.ecc.pointJac(S.curve);
      }
    }
    d = T.y.mul(sz2.mul(S.z)).subM(S.y);
    c2 = c.square();
    x1 = d.square();
    x2 = c
      .square()
      .mul(c)
      .addM(S.x.add(S.x).mul(c2));
    x = x1.subM(x2);
    y1 = S.x
      .mul(c2)
      .subM(x)
      .mul(d);
    y2 = S.y.mul(c.square().mul(c));
    y = y1.subM(y2);
    z = S.z.mul(c);
    return new sjcl.ecc.pointJac(this.curve, x, y, z);
  },
  doubl: function() {
    if (this.isIdentity) {
      return this;
    }
    var y2 = this.y.square(),
      a = y2.mul(this.x.mul(4)),
      b = y2.square().mul(8),
      z2 = this.z.square(),
      c = this.x
        .sub(z2)
        .mul(3)
        .mul(this.x.add(z2)),
      x = c
        .square()
        .subM(a)
        .subM(a),
      y = a
        .sub(x)
        .mul(c)
        .subM(b),
      z = this.y.add(this.y).mul(this.z);
    return new sjcl.ecc.pointJac(this.curve, x, y, z);
  },
  toAffine: function() {
    if (this.isIdentity || this.z.equals(0)) {
      return new sjcl.ecc.point(this.curve);
    }
    var zi = this.z.inverse(),
      zi2 = zi.square();
    return new sjcl.ecc.point(
      this.curve,
      this.x.mul(zi2).fullReduce(),
      this.y.mul(zi2.mul(zi)).fullReduce()
    );
  },
  mult: function(k, affine) {
    if (typeof k === "number") {
      k = [k];
    } else if (k.limbs !== undefined) {
      k = k.normalize().limbs;
    }
    var i,
      j,
      out = new sjcl.ecc.point(this.curve).toJac(),
      multiples = affine.multiples();
    for (i = k.length - 1; i >= 0; i--) {
      for (j = sjcl.bn.prototype.radix - 4; j >= 0; j -= 4) {
        out = out
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(multiples[(k[i] >> j) & 0xf]);
      }
    }
    return out;
  },
  mult2: function(k1, affine, k2, affine2) {
    if (typeof k1 === "number") {
      k1 = [k1];
    } else if (k1.limbs !== undefined) {
      k1 = k1.normalize().limbs;
    }
    if (typeof k2 === "number") {
      k2 = [k2];
    } else if (k2.limbs !== undefined) {
      k2 = k2.normalize().limbs;
    }
    var i,
      j,
      out = new sjcl.ecc.point(this.curve).toJac(),
      m1 = affine.multiples(),
      m2 = affine2.multiples(),
      l1,
      l2;
    for (i = Math.max(k1.length, k2.length) - 1; i >= 0; i--) {
      l1 = k1[i] | 0;
      l2 = k2[i] | 0;
      for (j = sjcl.bn.prototype.radix - 4; j >= 0; j -= 4) {
        out = out
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(m1[(l1 >> j) & 0xf])
          .add(m2[(l2 >> j) & 0xf]);
      }
    }
    return out;
  },
  isValid: function() {
    var z2 = this.z.square(),
      z4 = z2.square(),
      z6 = z4.mul(z2);
    return this.y
      .square()
      .equals(
        this.curve.b
          .mul(z6)
          .add(this.x.mul(this.curve.a.mul(z4).add(this.x.square())))
      );
  }
};
sjcl.ecc.curve = function(Field, r, a, b, x, y) {
  this.field = Field;
  this.r = Field.prototype.modulus.sub(r);
  this.a = new Field(a);
  this.b = new Field(b);
  this.G = new sjcl.ecc.point(this, new Field(x), new Field(y));
};
sjcl.ecc.curve.prototype.fromBits = function(bits) {
  var w = sjcl.bitArray,
    l = (this.field.prototype.exponent + 7) & -8,
    p = new sjcl.ecc.point(
      this,
      this.field.fromBits(w.bitSlice(bits, 0, l)),
      this.field.fromBits(w.bitSlice(bits, l, 2 * l))
    );
  if (!p.isValid()) {
    throw new sjcl.exception.corrupt("not on the curve!");
  }
  return p;
};
sjcl.ecc.curves = {
  c192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192,
    "0x662107c8eb94364e4b2dd7ce",
    -3,
    "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
  ),
  c224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224,
    "0xe95c1f470fc1ec22d6baa3a3d5c4",
    -3,
    "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
  ),
  c256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256,
    "0x4319055358e8617b0c46353d039cdaae",
    -3,
    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  ),
  c384: new sjcl.ecc.curve(
    sjcl.bn.prime.p384,
    "0x389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68c",
    -3,
    "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
  )
};
sjcl.ecc._dh = function(cn) {
  sjcl.ecc[cn] = {
    publicKey: function(curve, point) {
      this._curve = curve;
      this._curveBitLength = curve.r.bitLength();
      if (point instanceof Array) {
        this._point = curve.fromBits(point);
      } else {
        this._point = point;
      }
      this.get = function() {
        var pointbits = this._point.toBits();
        var len = sjcl.bitArray.bitLength(pointbits);
        var x = sjcl.bitArray.bitSlice(pointbits, 0, len / 2);
        var y = sjcl.bitArray.bitSlice(pointbits, len / 2);
        return { x: x, y: y };
      };
    },
    secretKey: function(curve, exponent) {
      this._curve = curve;
      this._curveBitLength = curve.r.bitLength();
      this._exponent = exponent;
      this.get = function() {
        return this._exponent.toBits();
      };
    },
    generateKeys: function(curve, paranoia, sec) {
      if (curve === undefined) {
        curve = 256;
      }
      if (typeof curve === "number") {
        curve = sjcl.ecc.curves["c" + curve];
        if (curve === undefined) {
          throw new sjcl.exception.invalid("no such curve");
        }
      }
      if (sec === undefined) {
        var sec = sjcl.bn.random(curve.r, paranoia);
      }
      var pub = curve.G.mult(sec);
      return {
        pub: new sjcl.ecc[cn].publicKey(curve, pub),
        sec: new sjcl.ecc[cn].secretKey(curve, sec)
      };
    }
  };
};
sjcl.ecc._dh("elGamal");
sjcl.ecc.elGamal.publicKey.prototype = {
  kem: function(paranoia) {
    var sec = sjcl.bn.random(this._curve.r, paranoia),
      tag = this._curve.G.mult(sec).toBits(),
      key = sjcl.hash.sha256.hash(this._point.mult(sec).toBits());
    return { key: key, tag: tag };
  }
};
sjcl.ecc.elGamal.secretKey.prototype = {
  unkem: function(tag) {
    return sjcl.hash.sha256.hash(
      this._curve
        .fromBits(tag)
        .mult(this._exponent)
        .toBits()
    );
  },
  dh: function(pk) {
    return sjcl.hash.sha256.hash(pk._point.mult(this._exponent).toBits());
  }
};
sjcl.ecc._dh("ecdsa");
sjcl.ecc.ecdsa.secretKey.prototype = {
  sign: function(hash, paranoia, fakeLegacyVersion, fixedKForTesting) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var R = this._curve.r,
      l = R.bitLength(),
      k = fixedKForTesting || sjcl.bn.random(R.sub(1), paranoia).add(1),
      r = this._curve.G.mult(k).x.mod(R),
      ss = sjcl.bn.fromBits(hash).add(r.mul(this._exponent)),
      s = fakeLegacyVersion
        ? ss
            .inverseMod(R)
            .mul(k)
            .mod(R)
        : ss.mul(k.inverseMod(R)).mod(R);
    return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
  }
};
sjcl.ecc.ecdsa.publicKey.prototype = {
  verify: function(hash, rs, fakeLegacyVersion) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var w = sjcl.bitArray,
      R = this._curve.r,
      l = this._curveBitLength,
      r = sjcl.bn.fromBits(w.bitSlice(rs, 0, l)),
      ss = sjcl.bn.fromBits(w.bitSlice(rs, l, 2 * l)),
      s = fakeLegacyVersion ? ss : ss.inverseMod(R),
      hG = sjcl.bn
        .fromBits(hash)
        .mul(s)
        .mod(R),
      hA = r.mul(s).mod(R),
      r2 = this._curve.G.mult2(hG, hA, this._point).x;
    if (
      r.equals(0) ||
      ss.equals(0) ||
      r.greaterEquals(R) ||
      ss.greaterEquals(R) ||
      !r2.equals(r)
    ) {
      if (fakeLegacyVersion === undefined) {
        return this.verify(hash, rs, true);
      } else {
        throw new sjcl.exception.corrupt("signature didn't check out");
      }
    }
    return true;
  }
};
sjcl.keyexchange.srp = {
  makeVerifier: function(I, P, s, group) {
    var x;
    x = sjcl.keyexchange.srp.makeX(I, P, s);
    x = sjcl.bn.fromBits(x);
    return group.g.powermod(x, group.N);
  },
  makeX: function(I, P, s) {
    var inner = sjcl.hash.sha1.hash(I + ":" + P);
    return sjcl.hash.sha1.hash(sjcl.bitArray.concat(s, inner));
  },
  knownGroup: function(i) {
    if (typeof i !== "string") {
      i = i.toString();
    }
    if (!sjcl.keyexchange.srp._didInitKnownGroups) {
      sjcl.keyexchange.srp._initKnownGroups();
    }
    return sjcl.keyexchange.srp._knownGroups[i];
  },
  _didInitKnownGroups: false,
  _initKnownGroups: function() {
    var i, size, group;
    for (i = 0; i < sjcl.keyexchange.srp._knownGroupSizes.length; i++) {
      size = sjcl.keyexchange.srp._knownGroupSizes[i].toString();
      group = sjcl.keyexchange.srp._knownGroups[size];
      group.N = new sjcl.bn(group.N);
      group.g = new sjcl.bn(group.g);
    }
    sjcl.keyexchange.srp._didInitKnownGroups = true;
  },
  _knownGroupSizes: [1024, 1536, 2048],
  _knownGroups: {
    1024: {
      N:
        "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
        "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
        "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
        "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
        "FD5138FE8376435B9FC61D2FC0EB06E3",
      g: 2
    },
    1536: {
      N:
        "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961" +
        "4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843" +
        "80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B" +
        "E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5" +
        "6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A" +
        "F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E" +
        "8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
      g: 2
    },
    2048: {
      N:
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
        "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
        "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
        "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
        "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
        "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
        "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
        "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
        "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
        "9E4AFF73",
      g: 2
    }
  }
};
sjcl.ecc.point.prototype.isValidPoint = function() {
  var self = this;
  var field_modulus = self.curve.field.modulus;
  if (self.isIdentity) {
    return false;
  }
  if (
    (new sjcl.bn(1).greaterEquals(self.x) && !self.x.equals(1)) ||
    (self.x.greaterEquals(field_modulus.sub(1)) && !self.x.equals(1))
  ) {
    return false;
  }
  if (
    (new sjcl.bn(1).greaterEquals(self.y) && !self.y.equals(1)) ||
    (self.y.greaterEquals(field_modulus.sub(1)) && !self.y.equals(1))
  ) {
    return false;
  }
  if (!self.isOnCurve()) {
    return false;
  }
  return true;
};
sjcl.ecc.point.prototype.isOnCurve = function() {
  var self = this;
  var field_order = self.curve.r;
  var component_a = self.curve.a;
  var component_b = self.curve.b;
  var field_modulus = self.curve.field.modulus;
  var left_hand_side = self.y.mul(self.y).mod(field_modulus);
  var right_hand_side = self.x
    .mul(self.x)
    .mul(self.x)
    .add(component_a.mul(self.x))
    .add(component_b)
    .mod(field_modulus);
  return left_hand_side.equals(right_hand_side);
};
sjcl.ecc.point.prototype.toString = function() {
  return "(" + this.x.toString() + ", " + this.y.toString() + ")";
};
sjcl.ecc.pointJac.prototype.toString = function() {
  return (
    "(" +
    this.x.toString() +
    ", " +
    this.y.toString() +
    ", " +
    this.z.toString() +
    ")"
  );
};
sjcl.ecc.curves.c256 = new sjcl.ecc.curve(
  sjcl.bn.pseudoMersennePrime(256, [
    [0, -1],
    [4, -1],
    [6, -1],
    [7, -1],
    [8, -1],
    [9, -1],
    [32, -1]
  ]),
  "0x14551231950b75fc4402da1722fc9baee",
  0,
  7,
  "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
);
sjcl.ecc.pointJac.prototype.add = function(T) {
  var S = this;
  if (S.curve !== T.curve) {
    throw "sjcl.ecc.add(): Points must be on the same curve to add them!";
  }
  if (S.isIdentity) {
    return T.toJac();
  } else if (T.isIdentity) {
    return S;
  }
  var z1z1 = S.z.square();
  var h = T.x.mul(z1z1).subM(S.x);
  var s2 = T.y.mul(S.z).mul(z1z1);
  if (h.equals(0)) {
    if (S.y.equals(T.y.mul(z1z1.mul(S.z)))) {
      return S.doubl();
    } else {
      return new sjcl.ecc.pointJac(S.curve);
    }
  }
  var hh = h.square();
  var i = hh
    .copy()
    .doubleM()
    .doubleM();
  var j = h.mul(i);
  var r = s2.sub(S.y).doubleM();
  var v = S.x.mul(i);
  var x = r
    .square()
    .subM(j)
    .subM(v.copy().doubleM());
  var y = r.mul(v.sub(x)).subM(S.y.mul(j).doubleM());
  var z = S.z
    .add(h)
    .square()
    .subM(z1z1)
    .subM(hh);
  return new sjcl.ecc.pointJac(this.curve, x, y, z);
};
sjcl.ecc.pointJac.prototype.doubl = function() {
  if (this.isIdentity) {
    return this;
  }
  var a = this.x.square();
  var b = this.y.square();
  var c = b.square();
  var d = this.x
    .add(b)
    .square()
    .subM(a)
    .subM(c)
    .doubleM();
  var e = a.mul(3);
  var f = e.square();
  var x = f.sub(d.copy().doubleM());
  var y = e.mul(d.sub(x)).subM(
    c
      .doubleM()
      .doubleM()
      .doubleM()
  );
  var z = this.z.mul(this.y).doubleM();
  return new sjcl.ecc.pointJac(this.curve, x, y, z);
};
sjcl.ecc.point.prototype.toBytesCompressed = function() {
  var header = this.y.mod(2).toString() == "0x0" ? 0x02 : 0x03;
  return [header].concat(sjcl.codec.bytes.fromBits(this.x.toBits()));
};
(function() {
  sjcl.hash.ripemd160 = function(hash) {
    if (hash) {
      this._h = hash._h.slice(0);
      this._buffer = hash._buffer.slice(0);
      this._length = hash._length;
    } else {
      this.reset();
    }
  };
  sjcl.hash.ripemd160.hash = function(data) {
    return new sjcl.hash.ripemd160().update(data).finalize();
  };
  sjcl.hash.ripemd160.prototype = {
    reset: function() {
      this._h = _h0.slice(0);
      this._buffer = [];
      this._length = 0;
      return this;
    },
    update: function(data) {
      if (typeof data === "string") data = sjcl.codec.utf8String.toBits(data);
      var i,
        b = (this._buffer = sjcl.bitArray.concat(this._buffer, data)),
        ol = this._length,
        nl = (this._length = ol + sjcl.bitArray.bitLength(data));
      for (i = (512 + ol) & -512; i <= nl; i += 512) {
        var words = b.splice(0, 16);
        for (var w = 0; w < 16; ++w) words[w] = _cvt(words[w]);
        _block.call(this, words);
      }
      return this;
    },
    finalize: function() {
      var b = sjcl.bitArray.concat(this._buffer, [sjcl.bitArray.partial(1, 1)]),
        l = (this._length + 1) % 512,
        z = (l > 448 ? 512 : 448) - l % 448,
        zp = z % 32;
      if (zp > 0) b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(zp, 0)]);
      for (; z >= 32; z -= 32) b.push(0);
      b.push(_cvt(this._length | 0));
      b.push(_cvt(Math.floor(this._length / 0x100000000)));
      while (b.length) {
        var words = b.splice(0, 16);
        for (var w = 0; w < 16; ++w) words[w] = _cvt(words[w]);
        _block.call(this, words);
      }
      var h = this._h;
      this.reset();
      for (var w = 0; w < 5; ++w) h[w] = _cvt(h[w]);
      return h;
    }
  };
  var _h0 = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  var _k1 = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  var _k2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  for (var i = 4; i >= 0; --i) {
    for (var j = 1; j < 16; ++j) {
      _k1.splice(i, 0, _k1[i]);
      _k2.splice(i, 0, _k2[i]);
    }
  }
  var _r1 = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8,
    3,
    10,
    14,
    4,
    9,
    15,
    8,
    1,
    2,
    7,
    0,
    6,
    13,
    11,
    5,
    12,
    1,
    9,
    11,
    10,
    0,
    8,
    12,
    4,
    13,
    3,
    7,
    15,
    14,
    5,
    6,
    2,
    4,
    0,
    5,
    9,
    7,
    12,
    2,
    10,
    14,
    1,
    3,
    8,
    11,
    6,
    15,
    13
  ];
  var _r2 = [
    5,
    14,
    7,
    0,
    9,
    2,
    11,
    4,
    13,
    6,
    15,
    8,
    1,
    10,
    3,
    12,
    6,
    11,
    3,
    7,
    0,
    13,
    5,
    10,
    14,
    15,
    8,
    12,
    4,
    9,
    1,
    2,
    15,
    5,
    1,
    3,
    7,
    14,
    6,
    9,
    11,
    8,
    12,
    2,
    10,
    0,
    4,
    13,
    8,
    6,
    4,
    1,
    3,
    11,
    15,
    0,
    5,
    12,
    2,
    13,
    9,
    7,
    10,
    14,
    12,
    15,
    10,
    4,
    1,
    5,
    8,
    7,
    6,
    2,
    13,
    14,
    0,
    3,
    9,
    11
  ];
  var _s1 = [
    11,
    14,
    15,
    12,
    5,
    8,
    7,
    9,
    11,
    13,
    14,
    15,
    6,
    7,
    9,
    8,
    7,
    6,
    8,
    13,
    11,
    9,
    7,
    15,
    7,
    12,
    15,
    9,
    11,
    7,
    13,
    12,
    11,
    13,
    6,
    7,
    14,
    9,
    13,
    15,
    14,
    8,
    13,
    6,
    5,
    12,
    7,
    5,
    11,
    12,
    14,
    15,
    14,
    15,
    9,
    8,
    9,
    14,
    5,
    6,
    8,
    6,
    5,
    12,
    9,
    15,
    5,
    11,
    6,
    8,
    13,
    12,
    5,
    12,
    13,
    14,
    11,
    8,
    5,
    6
  ];
  var _s2 = [
    8,
    9,
    9,
    11,
    13,
    15,
    15,
    5,
    7,
    7,
    8,
    11,
    14,
    14,
    12,
    6,
    9,
    13,
    15,
    7,
    12,
    8,
    9,
    11,
    7,
    7,
    12,
    7,
    6,
    15,
    13,
    11,
    9,
    7,
    15,
    11,
    8,
    6,
    6,
    14,
    12,
    13,
    5,
    14,
    13,
    13,
    7,
    5,
    15,
    5,
    8,
    11,
    14,
    14,
    6,
    14,
    6,
    9,
    12,
    9,
    12,
    5,
    15,
    8,
    8,
    5,
    12,
    9,
    12,
    5,
    14,
    6,
    8,
    13,
    6,
    5,
    15,
    13,
    11,
    11
  ];
  function _f0(x, y, z) {
    return x ^ y ^ z;
  }
  function _f1(x, y, z) {
    return (x & y) | (~x & z);
  }
  function _f2(x, y, z) {
    return (x | ~y) ^ z;
  }
  function _f3(x, y, z) {
    return (x & z) | (y & ~z);
  }
  function _f4(x, y, z) {
    return x ^ (y | ~z);
  }
  function _rol(n, l) {
    return (n << l) | (n >>> (32 - l));
  }
  function _cvt(n) {
    return (
      ((n & (0xff << 0)) << 24) |
      ((n & (0xff << 8)) << 8) |
      ((n & (0xff << 16)) >>> 8) |
      ((n & (0xff << 24)) >>> 24)
    );
  }
  function _block(X) {
    var A1 = this._h[0],
      B1 = this._h[1],
      C1 = this._h[2],
      D1 = this._h[3],
      E1 = this._h[4],
      A2 = this._h[0],
      B2 = this._h[1],
      C2 = this._h[2],
      D2 = this._h[3],
      E2 = this._h[4];
    var j = 0,
      T;
    for (; j < 16; ++j) {
      T = _rol(A1 + _f0(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f4(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 32; ++j) {
      T = _rol(A1 + _f1(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f3(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 48; ++j) {
      T = _rol(A1 + _f2(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f2(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 64; ++j) {
      T = _rol(A1 + _f3(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f1(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    for (; j < 80; ++j) {
      T = _rol(A1 + _f4(B1, C1, D1) + X[_r1[j]] + _k1[j], _s1[j]) + E1;
      A1 = E1;
      E1 = D1;
      D1 = _rol(C1, 10);
      C1 = B1;
      B1 = T;
      T = _rol(A2 + _f0(B2, C2, D2) + X[_r2[j]] + _k2[j], _s2[j]) + E2;
      A2 = E2;
      E2 = D2;
      D2 = _rol(C2, 10);
      C2 = B2;
      B2 = T;
    }
    T = this._h[1] + C1 + D2;
    this._h[1] = this._h[2] + D1 + E2;
    this._h[2] = this._h[3] + E1 + A2;
    this._h[3] = this._h[4] + A1 + B2;
    this._h[4] = this._h[0] + B1 + C2;
    this._h[0] = T;
  }
})();
sjcl.bn.ZERO = new sjcl.bn(0);
sjcl.bn.prototype.divRem = function(that) {
  if (typeof that !== "object") {
    that = new this._class(that);
  }
  var thisa = this.abs(),
    thata = that.abs(),
    quot = new this._class(0),
    ci = 0;
  if (!thisa.greaterEquals(thata)) {
    return [new sjcl.bn(0), this.copy()];
  } else if (thisa.equals(thata)) {
    return [new sjcl.bn(1), new sjcl.bn(0)];
  }
  for (; thisa.greaterEquals(thata); ci++) {
    thata.doubleM();
  }
  for (; ci > 0; ci--) {
    quot.doubleM();
    thata.halveM();
    if (thisa.greaterEquals(thata)) {
      quot.addM(1);
      thisa.subM(that).normalize();
    }
  }
  return [quot, thisa];
};
sjcl.bn.prototype.divRound = function(that) {
  var dr = this.divRem(that),
    quot = dr[0],
    rem = dr[1];
  if (rem.doubleM().greaterEquals(that)) {
    quot.addM(1);
  }
  return quot;
};
sjcl.bn.prototype.div = function(that) {
  var dr = this.divRem(that);
  return dr[0];
};
sjcl.bn.prototype.sign = function() {
  return this.greaterEquals(sjcl.bn.ZERO) ? 1 : -1;
};
sjcl.bn.prototype.neg = function() {
  return sjcl.bn.ZERO.sub(this);
};
sjcl.bn.prototype.abs = function() {
  if (this.sign() === -1) {
    return this.neg();
  } else return this;
};
sjcl.bn.prototype.shiftRight = function(that) {
  if ("number" !== typeof that) {
    throw new Error("shiftRight expects a number");
  }
  that = +that;
  if (that < 0) {
    return this.shiftLeft(that);
  }
  var a = new sjcl.bn(this);
  while (that >= this.radix) {
    a.limbs.shift();
    that -= this.radix;
  }
  while (that--) {
    a.halveM();
  }
  return a;
};
sjcl.bn.prototype.shiftLeft = function(that) {
  if ("number" !== typeof that) {
    throw new Error("shiftLeft expects a number");
  }
  that = +that;
  if (that < 0) {
    return this.shiftRight(that);
  }
  var a = new sjcl.bn(this);
  while (that >= this.radix) {
    a.limbs.unshift(0);
    that -= this.radix;
  }
  while (that--) {
    a.doubleM();
  }
  return a;
};
sjcl.bn.prototype.toNumber = function() {
  return this.limbs[0] | 0;
};
sjcl.bn.prototype.testBit = function(bitIndex) {
  var limbIndex = Math.floor(bitIndex / this.radix);
  var bitIndexInLimb = bitIndex % this.radix;
  if (limbIndex >= this.limbs.length) return 0;
  return (this.limbs[limbIndex] >>> bitIndexInLimb) & 1;
};
sjcl.bn.prototype.setBitM = function(bitIndex) {
  var limbIndex = Math.floor(bitIndex / this.radix);
  var bitIndexInLimb = bitIndex % this.radix;
  while (limbIndex >= this.limbs.length) this.limbs.push(0);
  this.limbs[limbIndex] |= 1 << bitIndexInLimb;
  this.cnormalize();
  return this;
};
sjcl.bn.prototype.modInt = function(n) {
  return this.toNumber() % n;
};
sjcl.bn.prototype.invDigit = function() {
  var radixMod = 1 + this.radixMask;
  if (this.limbs.length < 1) return 0;
  var x = this.limbs[0];
  if ((x & 1) == 0) return 0;
  var y = x & 3;
  y = (y * (2 - (x & 0xf) * y)) & 0xf;
  y = (y * (2 - (x & 0xff) * y)) & 0xff;
  y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;
  y = (y * (2 - (x * y) % radixMod)) % radixMod;
  return y > 0 ? radixMod - y : -y;
};
function nbits(x) {
  var r = 1,
    t;
  if ((t = x >>> 16) != 0) {
    x = t;
    r += 16;
  }
  if ((t = x >> 8) != 0) {
    x = t;
    r += 8;
  }
  if ((t = x >> 4) != 0) {
    x = t;
    r += 4;
  }
  if ((t = x >> 2) != 0) {
    x = t;
    r += 2;
  }
  if ((t = x >> 1) != 0) {
    x = t;
    r += 1;
  }
  return r;
}
sjcl.bn.prototype.am = function(i, x, w, j, c, n) {
  var xl = x & 0xfff,
    xh = x >> 12;
  while (--n >= 0) {
    var l = this.limbs[i] & 0xfff;
    var h = this.limbs[i++] >> 12;
    var m = xh * l + h * xl;
    l = xl * l + ((m & 0xfff) << 12) + w.limbs[j] + c;
    c = (l >> 24) + (m >> 12) + xh * h;
    w.limbs[j++] = l & 0xffffff;
  }
  return c;
};
var Montgomery = function(m) {
  this.m = m;
  this.mt = m.limbs.length;
  this.mt2 = this.mt * 2;
  this.mp = m.invDigit();
  this.mpl = this.mp & 0x7fff;
  this.mph = this.mp >> 15;
  this.um = (1 << (m.radix - 15)) - 1;
};
Montgomery.prototype.reduce = function(x) {
  var radixMod = x.radixMask + 1;
  while (x.limbs.length <= this.mt2) x.limbs[x.limbs.length] = 0;
  for (var i = 0; i < this.mt; ++i) {
    var j = x.limbs[i] & 0x7fff;
    var u0 =
      (j * this.mpl +
        (((j * this.mph + (x.limbs[i] >> 15) * this.mpl) & this.um) << 15)) &
      x.radixMask;
    j = i + this.mt;
    x.limbs[j] += this.m.am(0, u0, x, i, 0, this.mt);
    while (x.limbs[j] >= radixMod) {
      x.limbs[j] -= radixMod;
      x.limbs[++j]++;
    }
  }
  x.trim();
  x = x.shiftRight(this.mt * this.m.radix);
  if (x.greaterEquals(this.m)) x = x.sub(this.m);
  return x
    .trim()
    .normalize()
    .reduce();
};
Montgomery.prototype.square = function(x) {
  return this.reduce(x.square());
};
Montgomery.prototype.multiply = function(x, y) {
  return this.reduce(x.mul(y));
};
Montgomery.prototype.convert = function(x) {
  return x
    .abs()
    .shiftLeft(this.mt * this.m.radix)
    .mod(this.m);
};
Montgomery.prototype.revert = function(x) {
  return this.reduce(x.copy());
};
sjcl.bn.prototype.powermodMontgomery = function(e, m) {
  var i = e.bitLength(),
    k,
    r = new this._class(1);
  if (i <= 0) return r;
  else if (i < 18) k = 1;
  else if (i < 48) k = 3;
  else if (i < 144) k = 4;
  else if (i < 768) k = 5;
  else k = 6;
  if (i < 8 || !m.testBit(0)) {
    return this.powermod(e, m);
  }
  var z = new Montgomery(m);
  e.trim().normalize();
  var g = new Array(),
    n = 3,
    k1 = k - 1,
    km = (1 << k) - 1;
  g[1] = z.convert(this);
  if (k > 1) {
    var g2 = z.square(g[1]);
    while (n <= km) {
      g[n] = z.multiply(g2, g[n - 2]);
      n += 2;
    }
  }
  var j = e.limbs.length - 1,
    w,
    is1 = true,
    r2 = new this._class(),
    t;
  i = nbits(e.limbs[j]) - 1;
  while (j >= 0) {
    if (i >= k1) w = (e.limbs[j] >> (i - k1)) & km;
    else {
      w = (e.limbs[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
      if (j > 0) w |= e.limbs[j - 1] >> (this.radix + i - k1);
    }
    n = k;
    while ((w & 1) == 0) {
      w >>= 1;
      --n;
    }
    if ((i -= n) < 0) {
      i += this.radix;
      --j;
    }
    if (is1) {
      r = g[w].copy();
      is1 = false;
    } else {
      while (n > 1) {
        r2 = z.square(r);
        r = z.square(r2);
        n -= 2;
      }
      if (n > 0) r2 = z.square(r);
      else {
        t = r;
        r = r2;
        r2 = t;
      }
      r = z.multiply(r2, g[w]);
    }
    while (j >= 0 && (e.limbs[j] & (1 << i)) == 0) {
      r2 = z.square(r);
      t = r;
      r = r2;
      r2 = t;
      if (--i < 0) {
        i = this.radix - 1;
        --j;
      }
    }
  }
  return z.revert(r);
};
sjcl.ecc.ecdsa.secretKey.prototype.sign = function(
  hash,
  paranoia,
  k_for_testing
) {
  var R = this._curve.r,
    l = R.bitLength();
  var k;
  if (
    typeof k_for_testing === "object" &&
    k_for_testing.length > 0 &&
    typeof k_for_testing[0] === "number"
  ) {
    k = k_for_testing;
  } else if (
    typeof k_for_testing === "string" &&
    /^[0-9a-fA-F]+$/.test(k_for_testing)
  ) {
    k = sjcl.bn.fromBits(sjcl.codec.hex.toBits(k_for_testing));
  } else {
    k = sjcl.bn.random(R.sub(1), paranoia).add(1);
  }
  var r = this._curve.G.mult(k).x.mod(R);
  var s = sjcl.bn
    .fromBits(hash)
    .add(r.mul(this._exponent))
    .mul(k.inverseMod(R))
    .mod(R);
  return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
};
sjcl.ecc.ecdsa.publicKey.prototype.verify = function(hash, rs) {
  var w = sjcl.bitArray,
    R = this._curve.r,
    l = R.bitLength(),
    r = sjcl.bn.fromBits(w.bitSlice(rs, 0, l)),
    s = sjcl.bn.fromBits(w.bitSlice(rs, l, 2 * l)),
    sInv = s.inverseMod(R),
    hG = sjcl.bn
      .fromBits(hash)
      .mul(sInv)
      .mod(R),
    hA = r.mul(sInv).mod(R),
    r2 = this._curve.G.mult2(hG, hA, this._point).x;
  if (
    r.equals(0) ||
    s.equals(0) ||
    r.greaterEquals(R) ||
    s.greaterEquals(R) ||
    !r2.equals(r)
  ) {
    throw new sjcl.exception.corrupt("signature didn't check out");
  }
  return true;
};
sjcl.ecc.ecdsa.secretKey.prototype.canonicalizeSignature = function(rs) {
  var w = sjcl.bitArray,
    R = this._curve.r,
    l = R.bitLength();
  var r = sjcl.bn.fromBits(w.bitSlice(rs, 0, l)),
    s = sjcl.bn.fromBits(w.bitSlice(rs, l, 2 * l));
  if (
    !R.copy()
      .halveM()
      .greaterEquals(s)
  ) {
    s = R.sub(s);
  }
  return w.concat(r.toBits(l), s.toBits(l));
};
sjcl.ecc.ecdsa.secretKey.prototype.signDER = function(hash, paranoia) {
  return this.encodeDER(this.sign(hash, paranoia));
};
sjcl.ecc.ecdsa.secretKey.prototype.encodeDER = function(rs) {
  var w = sjcl.bitArray,
    R = this._curve.r,
    l = R.bitLength();
  var rb = sjcl.codec.bytes.fromBits(w.bitSlice(rs, 0, l)),
    sb = sjcl.codec.bytes.fromBits(w.bitSlice(rs, l, 2 * l));
  while (!rb[0] && rb.length) rb.shift();
  while (!sb[0] && sb.length) sb.shift();
  if (rb[0] & 0x80) rb.unshift(0);
  if (sb[0] & 0x80) sb.unshift(0);
  var buffer = [].concat(
    0x30,
    4 + rb.length + sb.length,
    0x02,
    rb.length,
    rb,
    0x02,
    sb.length,
    sb
  );
  return sjcl.codec.bytes.toBits(buffer);
};
var FIELD_MODULUS_PLUS_ONE_DIVIDED_BY_FOUR;
sjcl.ecc.ecdsa.secretKey.prototype.signWithRecoverablePublicKey = function(
  hash,
  paranoia,
  k_for_testing
) {
  var self = this;
  var hash_bits;
  if (
    typeof hash === "object" &&
    hash.length > 0 &&
    typeof hash[0] === "number"
  ) {
    hash_bits = hash;
  } else {
    throw new sjcl.exception.invalid("hash. Must be a bitArray");
  }
  var standard_signature = self.sign(hash_bits, paranoia, k_for_testing);
  var canonical_signature = self.canonicalizeSignature(standard_signature);
  var r_and_s = getRandSFromSignature(self._curve, canonical_signature);
  var public_key = self._curve.G.mult(sjcl.bn.fromBits(self.get()));
  var recovery_factor = calculateRecoveryFactor(
    self._curve,
    r_and_s.r,
    r_and_s.s,
    hash_bits,
    public_key
  );
  var value_to_prepend = recovery_factor + 27;
  var final_signature_bits = sjcl.bitArray.concat(
    [value_to_prepend],
    canonical_signature
  );
  return final_signature_bits;
};
sjcl.ecc.ecdsa.publicKey.recoverFromSignature = function(
  hash,
  signature,
  curve
) {
  if (!signature || signature instanceof sjcl.ecc.curve) {
    throw new sjcl.exception.invalid(
      "must supply hash and signature to recover public key"
    );
  }
  if (!curve) {
    curve = sjcl.ecc.curves["c256"];
  }
  var hash_bits;
  if (
    typeof hash === "object" &&
    hash.length > 0 &&
    typeof hash[0] === "number"
  ) {
    hash_bits = hash;
  } else {
    throw new sjcl.exception.invalid("hash. Must be a bitArray");
  }
  var signature_bits;
  if (
    typeof signature === "object" &&
    signature.length > 0 &&
    typeof signature[0] === "number"
  ) {
    signature_bits = signature;
  } else {
    throw new sjcl.exception.invalid("signature. Must be a bitArray");
  }
  var recovery_factor = signature_bits[0] - 27;
  if (recovery_factor < 0 || recovery_factor > 3) {
    throw new sjcl.exception.invalid(
      "signature. Signature must be generated with algorithm " +
        "that prepends the recovery factor in order to recover the public key"
    );
  }
  var r_and_s = getRandSFromSignature(curve, signature_bits.slice(1));
  var signature_r = r_and_s.r;
  var signature_s = r_and_s.s;
  var recovered_public_key_point = recoverPublicKeyPointFromSignature(
    curve,
    signature_r,
    signature_s,
    hash_bits,
    recovery_factor
  );
  var recovered_public_key = new sjcl.ecc.ecdsa.publicKey(
    curve,
    recovered_public_key_point
  );
  return recovered_public_key;
};
function getRandSFromSignature(curve, signature) {
  var r_length = curve.r.bitLength();
  return {
    r: sjcl.bn.fromBits(sjcl.bitArray.bitSlice(signature, 0, r_length)),
    s: sjcl.bn.fromBits(
      sjcl.bitArray.bitSlice(
        signature,
        r_length,
        sjcl.bitArray.bitLength(signature)
      )
    )
  };
}
function calculateRecoveryFactor(
  curve,
  r,
  s,
  hash_bits,
  original_public_key_point
) {
  var original_public_key_point_bits = original_public_key_point.toBits();
  for (var possible_factor = 0; possible_factor < 4; possible_factor++) {
    var resulting_public_key_point;
    try {
      resulting_public_key_point = recoverPublicKeyPointFromSignature(
        curve,
        r,
        s,
        hash_bits,
        possible_factor
      );
    } catch (err) {
      continue;
    }
    if (
      sjcl.bitArray.equal(
        resulting_public_key_point.toBits(),
        original_public_key_point_bits
      )
    ) {
      return possible_factor;
    }
  }
  throw new sjcl.exception.bug(
    "unable to calculate recovery factor from signature"
  );
}
function recoverPublicKeyPointFromSignature(
  curve,
  signature_r,
  signature_s,
  hash_bits,
  recovery_factor
) {
  var field_order = curve.r;
  var field_modulus = curve.field.modulus;
  recovery_factor = recovery_factor & 3;
  var compressed_point_y_coord_is_even = recovery_factor & 1;
  var use_second_candidate_key = recovery_factor >> 1;
  if (!FIELD_MODULUS_PLUS_ONE_DIVIDED_BY_FOUR) {
    FIELD_MODULUS_PLUS_ONE_DIVIDED_BY_FOUR = field_modulus.add(1).div(4);
  }
  var x;
  if (use_second_candidate_key) {
    x = signature_r.add(field_order);
  } else {
    x = signature_r;
  }
  var alpha = x
    .mul(x)
    .mul(x)
    .add(curve.a.mul(x))
    .add(curve.b)
    .mod(field_modulus);
  var beta = alpha.powermodMontgomery(
    FIELD_MODULUS_PLUS_ONE_DIVIDED_BY_FOUR,
    field_modulus
  );
  var y;
  var beta_is_even = beta.mod(2).equals(0);
  if (
    (beta_is_even && !compressed_point_y_coord_is_even) ||
    (!beta_is_even && compressed_point_y_coord_is_even)
  ) {
    y = beta;
  } else {
    y = field_modulus.sub(beta);
  }
  var generated_point_R = new sjcl.ecc.point(curve, x, y);
  if (!generated_point_R.isValidPoint()) {
    throw new sjcl.exception.corrupt(
      "point R. Not a valid point on the curve. Cannot recover public key"
    );
  }
  var message_e = sjcl.bn.fromBits(hash_bits);
  var message_e_neg = new sjcl.bn(0).sub(message_e).mod(field_order);
  var signature_r_inv = signature_r.inverseMod(field_order);
  var public_key_point = generated_point_R
    .mult2(signature_s, message_e_neg, curve.G)
    .mult(signature_r_inv);
  if (!public_key_point.isValidPoint()) {
    throw new sjcl.exception.corrupt(
      "public_key_point. Not a valid point on the curve. Cannot recover public key"
    );
  }
  if (
    !verify_raw(curve, message_e, signature_r, signature_s, public_key_point)
  ) {
    throw new sjcl.exception.corrupt("cannot recover public key");
  }
  return public_key_point;
}
function verify_raw(curve, e, r, s, public_key_point) {
  var field_order = curve.r;
  if (
    new sjcl.bn(1).greaterEquals(r) ||
    r.greaterEquals(new sjcl.bn(field_order))
  ) {
    return false;
  }
  if (
    new sjcl.bn(1).greaterEquals(s) ||
    s.greaterEquals(new sjcl.bn(field_order))
  ) {
    return false;
  }
  var s_mod_inverse_field_order = s.inverseMod(field_order);
  var u1 = e.mul(s_mod_inverse_field_order).mod(field_order);
  var u2 = r.mul(s_mod_inverse_field_order).mod(field_order);
  var point_computed = curve.G.mult2(u1, u2, public_key_point);
  return r.equals(point_computed.x.mod(field_order));
}
sjcl.bn.prototype.jacobi = function(that) {
  var a = this;
  that = new sjcl.bn(that);
  if (that.sign() === -1) return;
  if (a.equals(0)) {
    return 0;
  }
  if (a.equals(1)) {
    return 1;
  }
  var s = 0;
  var e = 0;
  while (!a.testBit(e)) e++;
  var a1 = a.shiftRight(e);
  if ((e & 1) === 0) {
    s = 1;
  } else {
    var residue = that.modInt(8);
    if (residue === 1 || residue === 7) {
      s = 1;
    } else if (residue === 3 || residue === 5) {
      s = -1;
    }
  }
  if (that.modInt(4) === 3 && a1.modInt(4) === 3) {
    s = -s;
  }
  if (a1.equals(1)) {
    return s;
  } else {
    return s * that.mod(a1).jacobi(a1);
  }
};
