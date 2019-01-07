'use strict';

const sjcl = require('./vendor/sjcl');
const tweetnacl = require('tweetnacl');

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
