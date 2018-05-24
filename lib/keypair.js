'use strict';

const nacl = require('./vendor/nacl');
const sjcl = require('./vendor/sjcl');

/**
 * Get sha256 hash string
 *
 * @param {String} bytes
 * @returns {String}
 * @private
 */
const sha256 = bytes => {
  let hash;
  hash = sjcl.codec.bytes.fromBits(
      sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits(bytes)),
  );
  return hash;
};

class KeyPair {
  constructor() {
    this.rawPub = '';
    this.rawPriv = '';
    this.generate();
  }

  /**
   * Initialize the generated private key and public key.
   */
  generate() {
    let srcKeyPair = nacl.sign.keyPair();
    let seed = srcKeyPair.publicKey;
    let keyPair = nacl.sign.keyPair.fromSeed(seed);

    this.rawPriv = Array.from(seed);
    this.rawPub = Array.from(keyPair.publicKey);
  };

  /**
   * Get encoded private key
   * @returns {String}
   */
  getEncPrivateKey() {
    if (!this.rawPriv) {
      throw new Error('require rawPriv');
    }
    let _rawPriv = sjcl.bitArray.concat([0xda, 0x37, 0x9f, 0x1], this.rawPriv);
    let nvec = sjcl.bitArray.concat(_rawPriv, [0x00]);
    let buf = sha256(sha256(nvec)).slice(0, 4);
    let result = sjcl.bitArray.concat(nvec, buf);
    return sjcl.codec.base58.encode(result);
  };

  /**
   * Get encoded public key
   * @returns {String}
   */
  getEncPublicKey() {
    if (!this.rawPub) {
      throw new Error('require rawPub');
    }
    const nvec = sjcl.bitArray.concat([0xb0, 0x1], this.rawPub);
    const buf = sha256(sha256(nvec)).slice(0, 4);
    const result = sjcl.bitArray.concat(nvec, buf);
    return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(result));
  };

  /**
   * Get hash address.
   * @returns {String}
   */
  getAddress() {
    if (!this.rawPub) {
      throw new Error('require rawPub');
    }
    const head = [0x01, 0x56, 0x1];
    const hash = sha256(this.rawPub).slice(12);
    const buffer = sjcl.bitArray.concat(head, hash);
    const buf_256 = sha256(sha256(buffer)).slice(0, 4);
    const result = sjcl.bitArray.concat(buffer, buf_256);
    return sjcl.codec.base58.encode(result);
  };

  // -------------------- static methods ---------------------
  /**
   * Get encoded public key
   * @param encPrivateKey
   * @returns {String}
   */
  static getEncPublicKey(encPrivateKey) {
    if (!encPrivateKey) {
      throw new Error('require the encPrivateKey');
    }
    let rawPriv = this.parsePrivateKey(encPrivateKey);

    if (!rawPriv) {
      throw new Error('can not parse the encPrivateKey');
    }

    // const keyPair = nacl.sign.keyPair.fromSeed(obj.rawPriv);
    const keyPair = nacl.sign.keyPair.fromSeed(rawPriv);
    return this._getPublicKey(
        Array.from(keyPair.publicKey),
    );
  };

  static _getPublicKey(rawPub) {
    if (!rawPub) {
      throw new Error('require publicKey');
    }

    // let nvec = sjcl.bitArray.concat([0xb0, type], rawPub);
    const nvec = sjcl.bitArray.concat([0xb0, 0x1], rawPub);
    const buf = sha256(sha256(nvec)).slice(0, 4);
    const result = sjcl.bitArray.concat(nvec, buf);
    return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(result));
  }

  static getAddress(encPublicKey) {
    if (!encPublicKey) {
      throw new Error('require rawPub');
    }
    const rawPub = KeyPair.parsePublicKey(encPublicKey);
    // let head = [0x01, 0x56, type];
    const head = [0x01, 0x56, 0x1];
    const hash = sha256(rawPub).slice(12);
    const buffer = sjcl.bitArray.concat(head, hash);
    const buf_256 = sha256(sha256(buffer)).slice(0, 4);
    const result = sjcl.bitArray.concat(buffer, buf_256);
    return sjcl.codec.base58.encode(result);
  };


  // Get real private key from encoded private key
  static parsePrivateKey(encPrivateKey) {
    let privKeyBits = sjcl.codec.base58.decode(encPrivateKey);

    if (
        privKeyBits[0] !== 0xda ||
        privKeyBits[1] !== 0x37 ||
        privKeyBits[2] !== 0x9f
    ) {
      throw new Error(`private key ${encPrivateKey} is invalid, header is wrong`);
    }

    if (privKeyBits[3] > 4 || privKeyBits[3] < 1) {
      throw new Error(`private key ${encPrivateKey} is invalid, type is wrong`);
    }

    let privateLength = privKeyBits.length;

    if (privKeyBits[privateLength - 5] !== 0x00) {
      throw new Error(`private key ${encPrivateKey} is invalid, compression bit is wrong`);
    }

    let type = privKeyBits[3];

    let addHeaderPriv = privKeyBits.slice(0, privateLength - 4);
    let privHash = privKeyBits.slice(privateLength - 4, privateLength);
    let calHash = sha256(sha256(addHeaderPriv)).slice(0, 4);

    if (privHash.join() !== calHash.join()) {
      throw new Error(`private key ${encPrivateKey} is invalid, hash is wrong`);
    }

    let rawPriv =  privKeyBits.slice(4, privateLength - 5);
    return rawPriv;
  };

  // Get public key from encoded public key
  static parsePublicKey(encPublicKey) {
    let publicKeyBytes = sjcl.codec.bytes.fromBits(
        sjcl.codec.hex.toBits(encPublicKey),
    );
    if (publicKeyBytes[0] !== 0xb0) {
      throw new Error(`public key ${encPublicKey} is invalid, header is wrong`);
    }
    if (publicKeyBytes[1] > 4 || publicKeyBytes[1] < 1) {
      throw new Error(`public key ${encPublicKey} is invalid, type is wrong`);
    }
    let publicLength = publicKeyBytes.length;

    let type = publicKeyBytes[1];
    let addHeaderPub = publicKeyBytes.slice(0, publicLength - 4);
    let pubHash = publicKeyBytes.slice(publicLength - 4, publicLength);
    let calHash = sha256(sha256(addHeaderPub)).slice(0, 4);
    if (pubHash.join() !== calHash.join()) {
      throw new Error(`public key ${encPublicKey} is invalid, hash is wrong`);
    }

    let rawPub = publicKeyBytes.slice(2, publicKeyBytes.length - 4);
    return rawPub;
  };


  static getKeyPair() {
    const keypair = new KeyPair();
    const encPrivateKey = keypair.getEncPrivateKey();
    const encPublicKey = keypair.getEncPublicKey();
    const address = keypair.getAddress();

    return {
      encPrivateKey,
      encPublicKey,
      address,
    };
  };

  /**
   * check encPrivateKey
   * @param  {String} encPrivateKey [encPrivateKey]
   * @return {Boolean}               []
   */
  static checkEncPrivateKey(encPrivateKey) {
    try {
      if (!encPrivateKey || (typeof encPrivateKey !== 'string')) {
        return false;
      }

      let privKeyBits = sjcl.codec.base58.decode(encPrivateKey.trim());

      if (
          privKeyBits[0] !== 0xda ||
          privKeyBits[1] !== 0x37 ||
          privKeyBits[2] !== 0x9f ||
          privKeyBits[3] > 4 ||
          privKeyBits[3] < 1
      ) {
        return false;
      }

      let privateLength = privKeyBits.length;

      if (privKeyBits[privateLength - 5] !== 0x00) {
        return false;
      }

      let type = privKeyBits[3];

      let addHeaderPriv = privKeyBits.slice(0, privateLength - 4);
      let privHash = privKeyBits.slice(privateLength - 4, privateLength);
      let calHash = sha256(sha256(addHeaderPriv)).slice(0, 4);

      if (privHash.join() !== calHash.join()) {
        return false;
      }

      return true;
    } catch (err) {
      return false;
    }
  }

  /**
   * check encPublicKey
   * @param  {String} encPublicKey [encPublicKey]
   * @return {Boolean}              []
   */
  static checkEncPublicKey(encPublicKey) {
    try {
      if (!encPublicKey || typeof encPublicKey !== 'string') {
        return false;
      }

      let publicKeyBytes = sjcl.codec.bytes.fromBits(
          sjcl.codec.hex.toBits(encPublicKey.trim()),
      );

      if (
        publicKeyBytes[0] !== 0xb0 ||
        publicKeyBytes[1] > 4 ||
        publicKeyBytes[1] < 1
      ) {
        return false;
      }

      let publicLength = publicKeyBytes.length;

      let type = publicKeyBytes[1];
      let addHeaderPub = publicKeyBytes.slice(0, publicLength - 4);
      let pubHash = publicKeyBytes.slice(publicLength - 4, publicLength);
      let calHash = sha256(sha256(addHeaderPub)).slice(0, 4);
      if (pubHash.join() !== calHash.join()) {
        return false;
      }

      return true;
    } catch (err) {
      return false;
    }
  }

  /**
   * check address
   * @param  {String} address [address]
   * @return {Boolean}         []
   */
  static checkAddress(address) {
    try {
      if (!address || typeof address !== 'string') {
        return false;
      }

      let addressArr = sjcl.codec.base58.decode(address.trim());
      let head = sjcl.bitArray.concat([0x01, 0x56, 0x1], []);

      if (
        !Array.isArray(addressArr) ||
        addressArr[0] !== head[0] ||
        addressArr[1] !== head[1] ||
        addressArr[2] !== head[2] ||
        addressArr.length !== 27
      ) {
        return false;
      }

      // addressArr = `addrHead` concat `addrHash`
      let arrLength = addressArr.length;
      let addrHead = addressArr.slice(0, arrLength - 4);
      let addrHash = addressArr.slice(arrLength - 4, arrLength);

      let testHash = sha256(sha256(addrHead)).slice(0, 4);

      if (addrHash.join() !== testHash.join()) {
        return false;
      }

      return true;
    } catch (err) {
      return false;
    }
  }

}

/**
 * Expose `KeyPair`
 */
module.exports = KeyPair;
