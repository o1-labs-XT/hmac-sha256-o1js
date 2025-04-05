import hmac
import hashlib
import binascii
import struct

def bytes_to_hex_blocks(b, block_size=4):
    """Convert bytes to hex string in blocks"""
    hex_str = binascii.hexlify(b).decode()
    return ' '.join(hex_str[i:i+block_size*2] for i in range(0, len(hex_str), block_size*2))

def debug_hmac_sha256():
    # Initial inputs
    key = "4q72JHgX89z3BkFMt6cwQxL1rD28jpN5UfVhIZYPbCSeuGovRaWmA0sD9ECtX7Jf"
    message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')
    block_size = 64  # 512 bits = 64 bytes

    # Step 1: Determine K0
    print("\n=== Step 1: Determine K0 ===")
    if len(key_bytes) > block_size:
        key_bytes = hashlib.sha256(key_bytes).digest()
    if len(key_bytes) < block_size:
        key_bytes = key_bytes + b'\x00' * (block_size - len(key_bytes))
    print(f"K0: {bytes_to_hex_blocks(key_bytes)}")

    # Step 2: K0 ^ ipad
    print("\n=== Step 2: K0 ^ ipad ===")
    k0_ipad = bytes((x ^ 0x36) for x in key_bytes)
    print(f"K0 ^ ipad: {bytes_to_hex_blocks(k0_ipad)}")

    # Step 3: (K0 ^ ipad) || message
    print("\n=== Step 3: (K0 ^ ipad) || message ===")
    inner_msg = k0_ipad + message_bytes
    print(f"(K0 ^ ipad) || message: {bytes_to_hex_blocks(inner_msg)}")

    # Step 4: H((K0 ^ ipad) || message)
    print("\n=== Step 4: H((K0 ^ ipad) || message) ===")
    inner_hash = hashlib.sha256(inner_msg).digest()
    print(f"H((K0 ^ ipad) || message): {bytes_to_hex_blocks(inner_hash)}")

    # Step 5: K0 ^ opad
    print("\n=== Step 5: K0 ^ opad ===")
    k0_opad = bytes((x ^ 0x5c) for x in key_bytes)
    print(f"K0 ^ opad: {bytes_to_hex_blocks(k0_opad)}")

    # Step 6: (K0 ^ opad) || H((K0 ^ ipad) || message)
    print("\n=== Step 6: (K0 ^ opad) || H((K0 ^ ipad) || message) ===")
    outer_msg = k0_opad + inner_hash
    print(f"(K0 ^ opad) || H((K0 ^ ipad) || message): {bytes_to_hex_blocks(outer_msg)}")

    # Step 7: H((K0 ^ opad) || H((K0 ^ ipad) || message))
    print("\n=== Step 7: Final HMAC ===")
    final_hash = hashlib.sha256(outer_msg).digest()
    print(f"H((K0 ^ opad) || H((K0 ^ ipad) || message)): {binascii.hexlify(final_hash).decode()}")

    # Verification
    print("\n=== Verification with standard HMAC ===")
    standard_hmac = hmac.new(key_bytes, message_bytes, hashlib.sha256).digest()
    print(f"Standard HMAC-SHA256: {binascii.hexlify(standard_hmac).decode()}")

if __name__ == "__main__":
    debug_hmac_sha256() 
