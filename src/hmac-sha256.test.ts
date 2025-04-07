import { UInt32, UInt8 } from 'o1js';
import { HMAC_SHA256 } from './hmac-sha256';
import crypto from 'crypto';

function bytesToUInt32Array(bytes: Uint8Array): UInt32[] {
  const result: UInt32[] = [];
  // Pad the bytes array to be a multiple of 4
  const paddedLength = Math.ceil(bytes.length / 4) * 4;
  const paddedBytes = new Uint8Array(paddedLength);
  paddedBytes.set(bytes);

  for (let i = 0; i < paddedLength; i += 4) {
    result.push(
      UInt32.fromBytesBE([
        UInt8.from(paddedBytes[i]),
        UInt8.from(paddedBytes[i + 1]),
        UInt8.from(paddedBytes[i + 2]),
        UInt8.from(paddedBytes[i + 3]),
      ])
    );
  }
  return result;
}

describe('HMAC-SHA256', () => {
  it('should match Node.js crypto implementation for multiple random inputs', () => {
    for (let i = 0; i < 100; i++) {
      const keyBytes = crypto.randomBytes(64);
      const messageBytes = crypto.randomBytes(64);

      const key = bytesToUInt32Array(keyBytes);
      const message = bytesToUInt32Array(messageBytes);

      const ourHmac = HMAC_SHA256.compute(key, message);
      const ourHmacHex = ourHmac.bytes
        .map((b) => b.toBigInt().toString(16).padStart(2, '0'))
        .join('');

      const nodeHmac = crypto
        .createHmac('sha256', keyBytes)
        .update(messageBytes)
        .digest('hex');

      expect(ourHmacHex).toBe(nodeHmac);
    }
  });

  it('should match Node.js crypto implementation for different key sizes (1-63 bytes)', () => {
    for (let i = 0; i < 100; i++) {
      const keySize = Math.floor(Math.random() * 63) + 1;
      const keyBytes = crypto.randomBytes(keySize);
      const messageBytes = crypto.randomBytes(64);

      const key = bytesToUInt32Array(keyBytes);
      const message = bytesToUInt32Array(messageBytes);

      const ourHmac = HMAC_SHA256.compute(key, message);
      const ourHmacHex = ourHmac.bytes
        .map((b) => b.toBigInt().toString(16).padStart(2, '0'))
        .join('');

      const nodeHmac = crypto
        .createHmac('sha256', keyBytes)
        .update(messageBytes)
        .digest('hex');

      expect(ourHmacHex).toBe(nodeHmac);
    }
  });
});
