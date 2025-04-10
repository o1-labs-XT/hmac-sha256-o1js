import { Bytes, Hash, UInt32, FlexibleBytes, Provable, UInt8 } from 'o1js';

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
 */
export class HMAC_SHA256 {
  static readonly IPAD = UInt32.from(0x36363636); // Inner padding constant
  static readonly OPAD = UInt32.from(0x5c5c5c5c); // Outer padding constant
  static readonly BLOCK_SIZE = 64; // Block size for SHA256 (512 bits / 64 bytes)

  /**
   * Computes HMAC-SHA256 for given key and message
   * @param key - The key for HMAC
   * @param message - The message to authenticate
   * @returns The HMAC hash as Bytes
   */
  static hmacSha256(key: FlexibleBytes, message: FlexibleBytes): Bytes {
    // Step 1: k_0
    const k0 = Bytes(this.BLOCK_SIZE).from(Bytes.from(key).bytes);

    // Convert padded key to UInt32 array for XOR operations
    const k0Uint32 = Provable.Array(UInt32, 16).empty();
    const k0Bytes = Provable.Array(UInt8, this.BLOCK_SIZE).empty();

    // Copy the key bytes into a provable array
    for (let i = 0; i < this.BLOCK_SIZE; i++) {
      k0Bytes[i] = k0.bytes[i];
    }

    // Construct each UInt32 from 4 bytes with proper byte ordering
    for (let i = 0; i < 16; i++) {
      k0Uint32[i] = UInt32.fromBytes([
        k0Bytes[i * 4 + 3],
        k0Bytes[i * 4 + 2],
        k0Bytes[i * 4 + 1],
        k0Bytes[i * 4 + 0],
      ]);
    }

    // Step 2: k_0 ^ ipad
    const k0IpadXor = Provable.Array(UInt32, 16).empty();
    for (let i = 0; i < 16; i++) {
      k0IpadXor[i] = k0Uint32[i].xor(this.IPAD);
    }

    // Step 3: (k_0 ^ ipad) || message
    const k0IpadBytes = Provable.Array(UInt8, this.BLOCK_SIZE).empty();
    for (let i = 0; i < 16; i++) {
      const ipadBytes = k0IpadXor[i].toBytes();
      k0IpadBytes[i * 4 + 0] = ipadBytes[3];
      k0IpadBytes[i * 4 + 1] = ipadBytes[2];
      k0IpadBytes[i * 4 + 2] = ipadBytes[1];
      k0IpadBytes[i * 4 + 3] = ipadBytes[0];
    }

    const messageBytes = Bytes.from(message).bytes;
    const innerBlock = Provable.Array(
      UInt8,
      this.BLOCK_SIZE + messageBytes.length
    ).empty();

    for (let i = 0; i < this.BLOCK_SIZE; i++) {
      innerBlock[i] = k0IpadBytes[i];
    }
    for (let i = 0; i < messageBytes.length; i++) {
      innerBlock[this.BLOCK_SIZE + i] = messageBytes[i];
    }

    // Step 4: H((k_0 ^ ipad) || message)
    const innerHash = Hash.SHA2_256.hash(innerBlock);

    // Step 5: k_0 ^ opad
    const k0OpadXor = Provable.Array(UInt32, 16).empty();
    for (let i = 0; i < 16; i++) {
      k0OpadXor[i] = k0Uint32[i].xor(this.OPAD);
    }

    // Step 6: (k_0 ^ opad) || H((k_0 ^ ipad) || message)
    const k0OpadBytes = Provable.Array(UInt8, this.BLOCK_SIZE).empty();
    for (let i = 0; i < 16; i++) {
      const opadBytes = k0OpadXor[i].toBytes();
      k0OpadBytes[i * 4 + 0] = opadBytes[3];
      k0OpadBytes[i * 4 + 1] = opadBytes[2];
      k0OpadBytes[i * 4 + 2] = opadBytes[1];
      k0OpadBytes[i * 4 + 3] = opadBytes[0];
    }

    const outerBlock = Provable.Array(UInt8, this.BLOCK_SIZE + 32).empty();
    for (let i = 0; i < this.BLOCK_SIZE; i++) {
      outerBlock[i] = k0OpadBytes[i];
    }
    for (let i = 0; i < 32; i++) {
      outerBlock[this.BLOCK_SIZE + i] = innerHash.bytes[i];
    }

    // Step 7: H((k_0 ^ opad) || H((k_0 ^ ipad) || message))
    return Hash.SHA2_256.hash(outerBlock);
  }
}
