'use strict';

const scrypt = require('scryptsy');
const aes = require('aes-js');
const util = require('./util');
const keypair = require('./keypair');

const keystore = {};

/**
 * Encrypt private key, get keystore string
 * @param {String} data
 * @param {String} password
 * @return {Promise<any>}
 */
keystore.encrypt = (data, password) => {
  let isPrivateKey = false;
  let address = '';
  if (!util.isValidString(data)) {
    throw new Error('data must be a non-empty string');
  }

  if (!util.isValidString(password)) {
    throw new Error('password must be a non-empty string');
  }

  if (keypair.checkEncPrivateKey(data)) {
    const encPublicKey = keypair.getEncPublicKey(data);
    address = keypair.getAddress(encPublicKey);
  } else {
    address = util.sha256(data);
  }

  return new Promise(function(resolve, reject) {
    try {
      const iv = util.getIv();
      const salt = util.getSalt();
      const N = 16384;
      const r = 8;
      const p = 1;
      const dkLen = 32;

      const result = scrypt(password, Buffer.from(salt), N, r, p, dkLen);
      const key  = util.bytesFromHex(result.toString('hex'));

      // Convert text to bytes
      const textBytes = aes.utils.utf8.toBytes(data);

      const aesCtr = new aes.ModeOfOperation.ctr(key, iv);
      const encryptedBytes = aesCtr.encrypt(textBytes);

      const encryptedHex = aes.utils.hex.fromBytes(encryptedBytes);

      const obj = {
        address: address,
        aesctr_iv: util.hexFrombytes(iv),
        cypher_text: encryptedHex,
        scrypt_params: {
          n: N,
          r: r,
          p: p,
          salt: util.hexFrombytes(salt)
        },
        version: 2
      };

      const encryptTxt = JSON.stringify(obj);
      resolve(encryptTxt);
    } catch (err) {
      reject(err);
    }
  });
};


 /**
 * Get private key by keystore
 * @param {String} keystore
 * @param {String} password
 * @return {Promise<any>}
 */
keystore.decrypt = (keystore, password) => {
  if (!util.isValidString(keystore)) {
    throw new Error('keystore must be a non-empty string');
  }

  if (!util.isValidString(password)) {
    throw new Error('password must be a non-empty string');
  }

  return new Promise(function(resolve, reject) {
    try {
      keystore = JSON.parse(keystore);
      const encryptedHex = keystore.cypher_text || '';
      const iv = util.bytesFromHex(keystore.aesctr_iv || '');
      const params = keystore.scrypt_params || {};
      const salt = util.bytesFromHex(params.salt);
      const N = params.n;
      const r = params.r;
      const p = params.p;
      const dkLen = 32;

      const result = scrypt(password, Buffer.from(salt), N, r, p, dkLen);
      const key  = util.bytesFromHex(result.toString("hex"));

      const encryptedBytes = aes.utils.hex.toBytes(encryptedHex);
      const aesCtr = new aes.ModeOfOperation.ctr(key, iv);
      const decryptedBytes = aesCtr.decrypt(encryptedBytes);
      // Convert our bytes back into text
      let decryptedText = aes.utils.utf8.fromBytes(decryptedBytes);

      let address = '';
      if (keypair.checkEncPrivateKey(decryptedText)) {
        const encPublicKey = keypair.getEncPublicKey(decryptedText);
        address = keypair.getAddress(encPublicKey);
      } else {
        address = util.sha256(decryptedText);
      }

      if (address !== keystore.address || 2 !== keystore.version) {
        decryptedText = '';
      }

      resolve(decryptedText);
    } catch (err) {
      reject(err);
    }
  });
};

module.exports = keystore;
