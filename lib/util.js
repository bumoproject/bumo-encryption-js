'use strict';

const tweetnacl = require('tweetnacl');
const hash = require('hash.js');
const sjcl = require('./vendor/sjcl');

const proto = exports;

proto.hexFrombytes = bytes => {
  return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(bytes));
};

proto.bytesFromHex = hex => {
  return sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(hex));
};

proto.getSalt = () => {
  return tweetnacl.randomBytes(32);
};

proto.getIv = () => {
  return tweetnacl.randomBytes(16);
};

proto.isValidString = (str) => {
  return (typeof str === 'string') && (str.trim().length > 0);
};

proto.sha256 = str => {
  return hash.sha256().update(str).digest('hex');
};
