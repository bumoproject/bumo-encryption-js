'use strict';

const sjcl = require('sjcl');
const is = require('is-type-of');
const CryptoJS = require('crypto-js');
const scrypt = require('./vendor/scrypt');
const Crypto = scrypt.Crypto;
const Crypto_scrypt = scrypt.Crypto_scrypt;

const keystore = {};

/**
 * Encrypt private key, get keystore json object
 * If encPrivateKey was null, return a new one, otherwise return itself
 *
 * @param {String} encPrivateKey
 * @param {String} password
 * @param {function} callback
 */
keystore.encrypt = (encPrivateKey, password, callback) => {
  // n is CPU cost parameter, if n is null, the default value is 16384
  const n = 16384;
  // r is memory cost parameter, if r is null, the default value is 8
  const r = 8;
  // p is parallelization parameter, if p is null, the default value is 1
  const p = 1;
  const dkLen = 32;
  let salt = sjcl.random.randomWords(32);
  let iv = sjcl.random.randomWords(16);

  Crypto_scrypt(password, salt, n, r, p, dkLen, function(dk) {
    let key = Crypto.util.bytesToHex(dk);

    let encrypted = CryptoJS.AES.encrypt(encPrivateKey, key, {
      iv: iv,
      mode: CryptoJS.mode.CTR,
      padding: CryptoJS.pad.NoPadding
    });

    let obj = {
      encrypted: encrypted,
      salt: salt,
      iv: iv,
    };

    callback(obj);
  });

};

/**
 * Get private key by keystore
 *
 * @param  {Object}   keystore
 * @param  {String}   password
 * @param  {Function} callback
 * @return {String}
 */
keystore.decrypt = (keystore, password, callback) => {
  if (!keystore) {
    throw new Error('require kestore');
  }
  if (!is.object(keystore)) {
    throw new TypeError('the type of `keystore must object.`')
  }
  if (!password) {
    throw new Error('require password');
  }

  // n is CPU cost parameter, if n is null, the default value is 16384
  const n = 16384;
  // r is memory cost parameter, if r is null, the default value is 8
  const r = 8;
  // p is parallelization parameter, if p is null, the default value is 1
  const p = 1;
  const dkLen = 32;

  let encrypted = keystore.encrypted;
  let salt = keystore.salt;
  let iv = keystore.iv;

  Crypto_scrypt(password, salt, n, r, p, dkLen, function(dk) {
    let key = Crypto.util.bytesToHex(dk);

    let decrypted = CryptoJS.AES.decrypt(encrypted, key, {
      mode: CryptoJS.mode.CTR,
      iv: iv,
      padding: CryptoJS.pad.NoPadding,
    });
    let privateKey =  decrypted.toString(CryptoJS.enc.Utf8);

    callback(privateKey);
  });
};

module.exports = keystore;
