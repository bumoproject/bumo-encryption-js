bumo-encryption
=======

bumo-encryption Sub module of [bumo-sdk-js](https://github.com/bumoproject/bumo-sdk-nodejs).

## bumo-encryption  Installation
```
npm install bumo-encryption --save
```

## bumo-encryption  Test
```
npm test
```

## bumo-encryption  Usage

```js
'use strict';

const encryption = require('bumo-encryption');

const KeyPair = encryption.keypair;
const signature = encryption.signature;
const keystore = encryption.keystore;

let kp = new KeyPair();
// Get encPrivateKey, encPublicKey, address
let encPrivateKey = kp.getEncPrivateKey();
let encPublicKey = kp.getEncPublicKey();
let address = kp.getAddress();


console.log('============= bof: ==============');
console.log(`EncPrivateKey is : ${encPrivateKey}`);
console.log(`EncPublicKey is : ${encPublicKey}`);
console.log(`Address hash is : ${address}`);
console.log('============= eof: ==============');

// Get keypair
let keypair = KeyPair.getKeyPair();

// Get encPublicKey
let encPublicKey = KeyPair.getEncPublicKey(encPrivateKey);

// Get address
let address = KeyPair.getAddress(encPublicKey);

// check encPrivateKey
KeyPair.checkEncPrivateKey(encPrivateKey);

// check encPublicKey
KeyPair.checkEncPublicKey(encPublicKey);

// check address
KeyPair.checkAddress(address);

// signature sign and verify
let sign = signature.sign('test', encPrivateKey);
let verify = signature.verify('test', sign, encPublicKey);

// keystore
let encData = keystore.encrypt(encPrivateKey, 'test');

let descData = keystore.decrypt(encData, 'test');
```

## License

[MIT](LICENSE)
