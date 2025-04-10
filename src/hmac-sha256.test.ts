import { Bytes } from 'o1js';
import { HMAC_SHA256 } from './hmac-sha256';
import crypto from 'crypto';

describe('HMAC-SHA256', () => {
  it('should match Node.js crypto implementation for block-size inputs (64 bytes)', () => {
    for (let i = 0; i < 100; i++) {
      const key = Bytes(64).random();
      const message = Bytes(64).random();

      const ourHmac = HMAC_SHA256.hmacSha256(key, message);
      const ourHmacHex = ourHmac.toHex();

      const nodeHmac = crypto
        .createHmac('sha256', key.toBytes())
        .update(message.toBytes())
        .digest('hex');

      expect(ourHmacHex).toBe(nodeHmac);
    }
  });

  it('should match Node.js crypto implementation for key size < block size (1-63 bytes)', () => {
    for (let i = 0; i < 100; i++) {
      const keySize = Math.floor(Math.random() * 63) + 1;
      const key = Bytes(keySize).random();
      const message = Bytes(64).random();

      const ourHmac = HMAC_SHA256.hmacSha256(key, message);
      const ourHmacHex = ourHmac.toHex();

      const nodeHmac = crypto
        .createHmac('sha256', key.toBytes())
        .update(message.toBytes())
        .digest('hex');

      expect(ourHmacHex).toBe(nodeHmac);
    }
  });
});
