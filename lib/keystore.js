'use strict';

const is = require('is-type-of');
const scrypt = require("scrypt");
const aes = require('aes-js');
const util = require('./util');
const keypair = require('./keypair');

const keystore = {};

/**
 * Encrypt private key, get keystore string
 * @param {String} encPrivateKey
 * @param {String} password
 * @return {String}
 */
keystore.encrypt = (encPrivateKey, password) => {
  if (!encPrivateKey) {
    throw new Error('require encPrivateKey');
  }

  if (!password) {
    throw new Error('require password');
  }

  if (!is.string(encPrivateKey)) {
    throw new Error('keystore must be a string')
  }


  if (!is.string(password)) {
    throw new Error('password must be a string')
  }

  try {
    const iv = util.getIv();
    const salt = util.getSalt();
    const N = 16384;
    const r = 8;
    const p = 1;
    const dkLen = 32;

    const result = scrypt.hashSync(password, {"N": N,"r": r,"p": p}, dkLen, Buffer.from(salt));
    const key  = util.bytesFromHex(result.toString('hex'));

    // Convert text to bytes
    const textBytes = aes.utils.utf8.toBytes(encPrivateKey);

    const aesCtr = new aes.ModeOfOperation.ctr(key, iv);
    const encryptedBytes = aesCtr.encrypt(textBytes);

    const encryptedHex = aes.utils.hex.fromBytes(encryptedBytes);

    const encPublicKey = keypair.getEncPublicKey(encPrivateKey);
    const address = keypair.getAddress(encPublicKey);

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

    return JSON.stringify(obj);
  } catch (err) {
    throw err;
  }
};

/**
 * Get private key by keystore
 * @param {String} keystore
 * @param {String} password
 * @returns {String}
 */
keystore.decrypt = (keystore, password) => {
  if (!keystore) {
    throw new Error('require kestore');
  }

  if (!password) {
    throw new Error('require password');
  }

  if (!is.string(keystore)) {
    throw new Error('keystore must be a string')
  }


  if (!is.string(password)) {
    throw new Error('password must be a string')
  }

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

    const result = scrypt.hashSync(password, {"N": N,"r": r,"p": p}, dkLen, Buffer.from(salt));
    const key  = util.bytesFromHex(result.toString("hex"));

    const encryptedBytes = aes.utils.hex.toBytes(encryptedHex);
    const aesCtr = new aes.ModeOfOperation.ctr(key, iv);
    const decryptedBytes = aesCtr.decrypt(encryptedBytes);
    // Convert our bytes back into text
    const decryptedText = aes.utils.utf8.fromBytes(decryptedBytes);

    if (keypair.checkEncPrivateKey(decryptedText)) {
      return decryptedText;
    }

    return '';
  } catch (err) {
    throw err;
  }
};

module.exports = keystore;
