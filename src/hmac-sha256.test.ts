import { Bytes } from 'o1js';
import { HMAC_SHA256 } from './hmac-sha256';
import crypto from 'crypto';

describe('HMAC-SHA256 Node.js Crypto Compatibility (Random Inputs)', () => {
  it('should match Node.js crypto implementation for block-size inputs (64 bytes)', () => {
    for (let i = 0; i < 100; i++) {
      const key = Bytes(64).random();
      const message = Bytes(64).random();

      const ourHmac = HMAC_SHA256.compute(key, message);
      const ourHmacHex = ourHmac.toHex();

      const nodeHmac = crypto
        .createHmac('sha256', key.toBytes())
        .update(message.toBytes())
        .digest('hex');

      expect(ourHmacHex).toBe(nodeHmac);
    }
  });

  it('should match Node.js crypto implementation for small inputs (1-63 bytes)', () => {
    for (let i = 0; i < 100; i++) {
      const keySize = Math.floor(Math.random() * 63) + 1; // 1 to 63 (inclusive)
      const key = Bytes(keySize).random();
      const messagesize = Math.floor(Math.random() * 63) + 1; // 1 to 63 (inclusive)
      const message = Bytes(messagesize).random();

      const ourHmac = HMAC_SHA256.compute(key, message);
      const ourHmacHex = ourHmac.toHex();

      const nodeHmac = crypto
        .createHmac('sha256', key.toBytes())
        .update(message.toBytes())
        .digest('hex');

      expect(ourHmacHex).toBe(nodeHmac);
    }
  });

  it('should match Node.js crypto implementation for large inputs (65-512 bytes)', () => {
    for (let i = 0; i < 100; i++) {
      const keySize = Math.floor(Math.random() * 448) + 65; // 65 to 512 (inclusive)
      const key = Bytes(keySize).random();
      const messagesize = Math.floor(Math.random() * 448) + 65; // 65 to 512 (inclusive)
      const message = Bytes(messagesize).random();

      const ourHmac = HMAC_SHA256.compute(key, message);
      const ourHmacHex = ourHmac.toHex();

      const nodeHmac = crypto
        .createHmac('sha256', key.toBytes())
        .update(message.toBytes())
        .digest('hex');

      expect(ourHmacHex).toBe(nodeHmac);
    }
  });
});

describe('HMAC-SHA256 RFC 4231 Test Vectors', () => {
  // Test Case 1 - Basic test case with key length < block size
  it('should pass RFC 4231 Test Case 1', () => {
    const key = Bytes.fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const data = Bytes.fromString('Hi There');

    const ourHmac = HMAC_SHA256.compute(key, data);
    const expectedHmac =
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';

    expect(ourHmac.toHex()).toBe(expectedHmac);
  });

  // Test Case 2 - Test with key and data that is the ASCII string "what do ya want for nothing?"
  it('should pass RFC 4231 Test Case 2', () => {
    const key = Bytes.fromString('Jefe');
    const data = Bytes.fromString('what do ya want for nothing?');

    const ourHmac = HMAC_SHA256.compute(key, data);
    const expectedHmac =
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843';

    expect(ourHmac.toHex()).toBe(expectedHmac);
  });

  // Test Case 3 - Test with key and data that are long hex strings
  it('should pass RFC 4231 Test Case 3', () => {
    const key = Bytes.fromHex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const data = Bytes.fromHex(
      'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
    );

    const ourHmac = HMAC_SHA256.compute(key, data);
    const expectedHmac =
      '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe';

    expect(ourHmac.toHex()).toBe(expectedHmac);
  });

  // Test Case 4 - Test with key and data that are long hex strings
  it('should pass RFC 4231 Test Case 4', () => {
    const key = Bytes.fromHex(
      '0102030405060708090a0b0c0d0e0f10111213141516171819'
    );
    const data = Bytes.fromHex(
      'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'
    );

    const ourHmac = HMAC_SHA256.compute(key, data);
    const expectedHmac =
      '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b';

    expect(ourHmac.toHex()).toBe(expectedHmac);
  });

  // Test Case 5 - Test with truncation to 128 bits
  it('should pass RFC 4231 Test Case 5 (without truncation)', () => {
    const key = Bytes.fromHex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c');
    const data = Bytes.fromString('Test With Truncation');

    const ourHmac = HMAC_SHA256.compute(key, data);
    const expectedHmac =
      'a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5';

    expect(ourHmac.toHex()).toBe(expectedHmac);
  });

  // Test Case 6 - Test with key larger than block size
  it('should pass RFC 4231 Test Case 6', () => {
    const key = Bytes.fromHex(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    );
    const data = Bytes.fromString(
      'Test Using Larger Than Block-Size Key - Hash Key First'
    );

    const ourHmac = HMAC_SHA256.compute(key, data);
    const expectedHmac =
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54';

    expect(ourHmac.toHex()).toBe(expectedHmac);
  });

  // Test Case 7 - Test with key and data larger than block size
  it('should pass RFC 4231 Test Case 7', () => {
    const key = Bytes.fromHex(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    );
    const data = Bytes.fromString(
      'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.'
    );

    const ourHmac = HMAC_SHA256.compute(key, data);
    const expectedHmac =
      '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2';

    expect(ourHmac.toHex()).toBe(expectedHmac);
  });
});
