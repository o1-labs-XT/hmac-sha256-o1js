import { Bytes, Hash, Provable, UInt32, UInt8 } from 'o1js';

/**
 * Implementation of HMAC-SHA256 (Hash-based Message Authentication Code using SHA-256)
 * Following the standard HMAC construction:
 * HMAC(K,m) = H((k_0 ^ opad) || H((k_0 ^ ipad) || m))
 * where:
 * - k_0 is the input key (padded/hashed if necessary)
 * - ipad is the inner padding (0x36 repeated)
 * - opad is the outer padding (0x5c repeated)
 * - H is SHA-256 hash function
 * - || denotes concatenation
 * - ^ denotes XOR operation
 *
 * Note: The current implementation does not handle key/message padding or truncation.
 * Both inputs must be pre-processed to match the required block size.
 */
export class HMAC_SHA256 {
  static readonly IPAD = UInt32.from(0x36363636); // Inner padding constant
  static readonly OPAD = UInt32.from(0x5c5c5c5c); // Outer padding constant

  /**
   * Computes HMAC-SHA256 for given key and message
   * @param key - Must be exactly 16 UInt32 values (64 bytes)
   * @param message - Must be exactly 16 UInt32 values (64 bytes)
   * @returns The HMAC hash as Bytes
   */
  static compute(key: UInt32[], message: UInt32[]): Bytes {
    // Step 1: k_0 is the input key
    const k0 = key;

    // Step 2: k_0 ^ ipad (XOR key with inner padding)
    const k0XorIpad = Provable.Array(UInt32, 16).empty();
    for (let i = 0; i < key.length; i++) {
      k0XorIpad[i] = k0[i].xor(UInt32.from(this.IPAD));
    }

    // Step 5: k_0 ^ opad (XOR key with outer padding)
    const k0XorOpad = Provable.Array(UInt32, 16).empty();
    for (let i = 0; i < key.length; i++) {
      k0XorOpad[i] = k0[i].xor(UInt32.from(this.OPAD));
    }

    // Step 3: Concatenate (k_0 ^ ipad) || message
    const innerBlock = Provable.Array(UInt32, 32).empty();
    for (let i = 0; i < 16; i++) {
      innerBlock[i] = k0XorIpad[i];
      innerBlock[i + 16] = message[i];
    }

    // Convert inner block to bytes for hashing
    const innerBlockBytes = Provable.Array(UInt8, 128).empty();
    for (let i = 0; i < innerBlock.length; i++) {
      const wordBytes = innerBlock[i].toBytes();
      innerBlockBytes[i * 4 + 0] = wordBytes[3];
      innerBlockBytes[i * 4 + 1] = wordBytes[2];
      innerBlockBytes[i * 4 + 2] = wordBytes[1];
      innerBlockBytes[i * 4 + 3] = wordBytes[0];
    }

    // Step 4: Calculate inner hash H((k_0 ^ ipad) || message)
    const innerHash = Hash.SHA2_256.hash(innerBlockBytes);
    const innerHashBytes = Provable.Array(UInt8, 32).empty();
    for (let i = 0; i < 32; i++) {
      innerHashBytes[i] = innerHash.bytes[i];
    }
    const innerHashUInt32 = Provable.Array(UInt32, 8).empty();
    for (let i = 0; i < innerHashBytes.length / 4; i++) {
      innerHashUInt32[i] = UInt32.fromBytesBE([
        innerHashBytes[i * 4],
        innerHashBytes[i * 4 + 1],
        innerHashBytes[i * 4 + 2],
        innerHashBytes[i * 4 + 3],
      ]);
    }

    // Step 6: Concatenate (k_0 ^ opad) || H((k_0 ^ ipad) || message)
    const outerBlock = Provable.Array(UInt32, 24).empty();
    for (let i = 0; i < 16; i++) {
      outerBlock[i] = k0XorOpad[i];
    }
    for (let i = 0; i < 8; i++) {
      outerBlock[i + 16] = innerHashUInt32[i];
    }

    // Convert outer block to bytes for final hashing
    const outerBlockBytes = Provable.Array(UInt8, 96).empty();
    for (let i = 0; i < outerBlock.length; i++) {
      const wordBytes = outerBlock[i].toBytes();
      outerBlockBytes[i * 4] = wordBytes[3];
      outerBlockBytes[i * 4 + 1] = wordBytes[2];
      outerBlockBytes[i * 4 + 2] = wordBytes[1];
      outerBlockBytes[i * 4 + 3] = wordBytes[0];
    }

    // Step 7: Final hash H((k_0 ^ opad) || H((k_0 ^ ipad) || message))
    return Hash.SHA2_256.hash(outerBlockBytes);
  }
}
