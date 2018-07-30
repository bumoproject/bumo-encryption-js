'use strict';

require('chai').should();
const encryption = require('../lib');

const KeyPair = encryption.keypair;
const signature = encryption.signature;
const keystore = encryption.keystore;

describe('Test bumo-encryption', function() {
  const kp = KeyPair.getKeyPair();

  it('test: getKeyPair', function() {
    kp.encPrivateKey.should.be.a('string');
    kp.encPublicKey.should.be.a('string');
    kp.address.should.be.a('string');
    kp.should.be.a('object');
    kp.should.have.property('encPrivateKey').with.lengthOf(56);
    kp.should.have.property('encPublicKey').with.lengthOf(76);
    kp.should.have.property('address').with.lengthOf(36);
    const checkPrivateKey = KeyPair.checkEncPrivateKey(kp.encPrivateKey);
    const checkPublickKey = KeyPair.checkEncPublicKey(kp.encPublicKey);
    const checkAddress = KeyPair.checkAddress(kp.address);
    checkPrivateKey.should.equal(true);
    checkPublickKey.should.equal(true);
    checkAddress.should.equal(true);
  });

  it('test: getEncPublicKey', function() {
    const encPublicKey = KeyPair.getEncPublicKey(kp.encPrivateKey);
    const checkPrivateKey = KeyPair.checkEncPublicKey(encPublicKey);
    checkPrivateKey.should.equal(true);
  });

  it('test: getAddress', function() {
    const encPublicKey = KeyPair.getEncPublicKey(kp.encPrivateKey);
    const address = KeyPair.getAddress(encPublicKey);
    const checkAddress = KeyPair.checkAddress(address);
    checkAddress.should.equal(true);
  });

  it('test: signature sign and verify', function() {
    const sign = signature.sign('test', kp.encPrivateKey);
    const verify = signature.verify('test', sign, kp.encPublicKey);

    const signII = signature.sign('test', kp.encPrivateKey);
    const verifyII = signature.verify('test2', signII, kp.encPublicKey);
    sign.should.be.a('string');
    sign.should.have.lengthOf(128);
    verify.should.be.a('boolean');
    verify.should.equal(true);
    verifyII.should.equal(false);
  });

  it('test: keystore encrypt', function() {
    let result = keystore.encrypt('privbse57qwJ9itsVt45f1sFSfQjSKGMY8yscjFSgWhpju4uoa4BQAoL', '123456');
    result.should.be.a('string');
    result = JSON.parse(result);
    result.should.have.property('address');
    result.should.have.property('aesctr_iv');
    result.should.have.property('cypher_text');
    result.should.have.property('scrypt_params');
    result.should.have.property('version');
  });

  it('test: keystore decrypt', function() {
    const result = keystore.encrypt('privbse57qwJ9itsVt45f1sFSfQjSKGMY8yscjFSgWhpju4uoa4BQAoL', '123456');
    let decrypt = keystore.decrypt(result, '123456');
    decrypt.should.be.a('string');
    decrypt.should.equal('privbse57qwJ9itsVt45f1sFSfQjSKGMY8yscjFSgWhpju4uoa4BQAoL');
    decrypt = keystore.decrypt(result, '1234567');
    decrypt.should.be.a('string');
    decrypt.should.equal('');
  });

  it('test: checkAddress', function() {
    const result = KeyPair.checkAddress('buQgE36mydaWh7k4UVdLy5cfBLiPDSVhUoPq');
    result.should.equal(true);
  });

});
