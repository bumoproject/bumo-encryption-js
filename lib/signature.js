'use strict';

const is = require('is-type-of');
const nacl = require('./vendor/nacl');
const sjcl = require('./vendor/sjcl');
const KeyPair = require('./keypair');
const signature = {};

/**
 * Generate the signature
 *
 * @param {String} message
 * @param {String} encPrivateKey
 * @returns {String}
 */
signature.sign = (message, encPrivateKey) => {
  if (!message || !encPrivateKey) {
    throw new Error('require message or encPrivateKey');
  }
  const privateKey = KeyPair.parsePrivateKey(encPrivateKey);
  if (!is.array(privateKey)) {
    throw new Error('private key format is incorrect.')
  }

  let keyPair = nacl.sign.keyPair.fromSeed(privateKey);
  let signBytes = nacl.sign.detached(message, keyPair.secretKey);
  return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(signBytes));
};



/**
 * Verify the signature
 *
 * @param  {String} message
 * @param  {String} signature
 * @param  {Array} encPublicKey
 * @return {Boolean}
 */
signature.verify = (message, signature, encPublicKey) => {
  if (!message || !signature || !encPublicKey) {
    throw new Error('require message or signature or encPublicKey.');
  }
  const publicKey = KeyPair.parsePublicKey(encPublicKey);
  if (!is.array(publicKey)) {
    throw new Error('public key format is incorrect.')
  }
  let signatureBytes = sjcl.codec.bytes.fromBits(
    sjcl.codec.hex.toBits(signature)
  );

  return nacl.sign.detached.verify(
    message,
    signatureBytes,
    publicKey,
  );
};


module.exports = signature;
