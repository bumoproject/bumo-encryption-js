'use strict';

require('chai').should();
const encryption = require('../lib');
const util = require('../lib/util');

const KeyPair = encryption.keypair;
const signature = encryption.signature;
const keystore = encryption.keystore;

describe('Test bumo-encryption', function() {
  const kp = KeyPair.getKeyPair();

  it('test: sign', function() {
    let privateKey = "privbz5r4XbBQ6Cwniw4E15XZTnfJnfDzmxLTtnDerMhoJywJEWB4Gkz";
    let transactionBlob = "0a24627551656357594648656d64483873396254597357756b3662766473776e4a4a61435433100118a08d0620e807321a7472616e73616374696f6e20637265617465206163636f756e743a5708041224627551656357594648656d64483873396254597357756b3662766473776e4a4a614354331a1066697273745365746d657461646174613a1b0a0a666972745365744b6579120d666972737453657456616c7565";
    let transactionBytes = util.bytesFromHex(transactionBlob);
    const signData = signature.sign(transactionBytes, privateKey);
    const publicKey = KeyPair.getEncPublicKey(privateKey);
    console.log(signData);
    console.log(publicKey);
  });

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
    const encPublicKeyStatus = KeyPair.checkEncPublicKey(encPublicKey);
    encPublicKeyStatus.should.equal(true);
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

  it('test: checkEncPrivatekey', function() {
    let data = KeyPair.checkEncPrivateKey('privbzEnfKU8GGN5tHWRd2CevoWbTw1QccLFGgdujgFQwiPjzwBLqL4f');
    data.should.be.a('boolean');
    data.should.equal(true);
    data = KeyPair.checkEncPrivateKey('');
    data.should.be.a('boolean');
    data.should.equal(false);
  });

  it('test: checkEncPublicKey', function() {
    let data = KeyPair.checkEncPublicKey('b001ea89a53060b257d34cdc25f064e53ae0fe3ce053b18ec71ba8dc2abe12cb059826888fa0');
    data.should.be.a('boolean');
    data.should.equal(true);
    data = KeyPair.checkEncPublicKey('');
    data.should.be.a('boolean');
    data.should.equal(false);
  });

  it('test: checkAddress', function() {
    const result = KeyPair.checkAddress('buQgE36mydaWh7k4UVdLy5cfBLiPDSVhUoPq');
    result.should.equal(true);
  });



});
