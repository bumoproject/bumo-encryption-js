'use strict';

var should = require('chai').should();
var encryption = require('../lib');

var KeyPair = encryption.keypair;
var signature = encryption.signature;
var keystore = encryption.keystore;

describe('Test bumo-encryption', function() {
  var kp = KeyPair.getKeyPair();

  it('test: getKeyPair', function() {
    kp.encPrivateKey.should.be.a('string');
    kp.encPublicKey.should.be.a('string');
    kp.address.should.be.a('string');
    kp.should.be.a('object');
    kp.should.have.property('encPrivateKey').with.lengthOf(56);
    kp.should.have.property('encPublicKey').with.lengthOf(76);
    kp.should.have.property('address').with.lengthOf(36);
    var checkPrivateKey = KeyPair.checkEncPrivateKey(kp.encPrivateKey)
    var checkPublickKey = KeyPair.checkEncPublicKey(kp.encPublicKey)
    var checkAddress = KeyPair.checkAddress(kp.address)
    checkPrivateKey.should.equal(true);
    checkPublickKey.should.equal(true);
    checkAddress.should.equal(true);
  });

  it('test: getEncPublicKey', function() {
    var encPublicKey = KeyPair.getEncPublicKey(kp.encPrivateKey);
    var checkPrivateKey = KeyPair.checkEncPublicKey(encPublicKey);
    checkPrivateKey.should.equal(true);
  });

  it('test: getAddress', function() {
    var encPublicKey = KeyPair.getEncPublicKey(kp.encPrivateKey);
    var address = KeyPair.getAddress(encPublicKey);
    var checkAddress = KeyPair.checkAddress(address);
    checkAddress.should.equal(true);
  });

  it('test: signature sign and verify', function() {
    var sign = signature.sign('test', kp.encPrivateKey);
    var verify = signature.verify('test', sign, kp.encPublicKey);

    var signII = signature.sign('test', kp.encPrivateKey);
    var verifyII = signature.verify('test2', signII, kp.encPublicKey);
    sign.should.be.a('string');
    sign.should.have.lengthOf(128);
    verify.should.be.a('boolean');
    verify.should.equal(true);
    verifyII.should.equal(false);
  });

  it('test: keystore', function() {
    keystore.encrypt(kp.encPrivateKey, 'test', function(encData) {
      keystore.decrypt(encData, 'test', function(descData) {
        // get encPrivateKey
        descData.should.be.a('string');
        descData.should.equal(kp.encPrivateKey);
      });
    });
  });

  it('test: checkAddress', function() {
    var result = KeyPair.checkAddress('buQgE36mydaWh7k4UVdLy5cfBLiPDSVhUoPq');
    result.should.equal(true);
  });

});
