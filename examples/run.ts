import { Provable,UInt32, UInt8, ZkProgram } from 'o1js';
import { HMAC_SHA256 } from '../src/hmac-sha256.js';

export let hmacSha256ZkProgram = ZkProgram({
  name: 'hmac-sha256-verify',
  publicOutput: Provable.Array(UInt8, 32), // HMAC-SHA256 Hash
  methods: {
    verifyHmac: {
      privateInputs: [
        Provable.Array(UInt32, 16), // Key
        Provable.Array(UInt32, 16), // Message
      ],

      async method(key: UInt32[], message: UInt32[]) {
        const hash = HMAC_SHA256.compute(key, message);
        return { publicOutput: hash.bytes };
      },
    },
  },
});

// 4q72JHgX89z3BkFMt6cwQxL1rD28jpN5UfVhIZYPbCSeuGovRaWmA0sD9ECtX7Jf
const key = [
  UInt32.from(0x34713732),
  UInt32.from(0x4a486758),
  UInt32.from(0x38397a33),
  UInt32.from(0x426b464d),
  UInt32.from(0x74366377),
  UInt32.from(0x51784c31),
  UInt32.from(0x72443238),
  UInt32.from(0x6a704e35),
  UInt32.from(0x55665668),
  UInt32.from(0x495a5950),
  UInt32.from(0x62435365),
  UInt32.from(0x75476f76),
  UInt32.from(0x5261576d),
  UInt32.from(0x41307344),
  UInt32.from(0x39454374),
  UInt32.from(0x58374a66),
];

// ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
const message = [
  UInt32.from(0x41424344),
  UInt32.from(0x45464748),
  UInt32.from(0x494a4b4c),
  UInt32.from(0x4d4e4f50),
  UInt32.from(0x51525354),
  UInt32.from(0x55565758),
  UInt32.from(0x595a6162),
  UInt32.from(0x63646566),
  UInt32.from(0x6768696a),
  UInt32.from(0x6b6c6d6e),
  UInt32.from(0x6f707172),
  UInt32.from(0x73747576),
  UInt32.from(0x7778797a),
  UInt32.from(0x30313233),
  UInt32.from(0x34353637),
  UInt32.from(0x38392b2f),
];

let { verifyHmac } = await hmacSha256ZkProgram.analyzeMethods();

console.log(verifyHmac.summary());

console.time('Compile');
const forceRecompileEnabled = false;
await hmacSha256ZkProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('Compile');

console.time('Prove');
let { proof } = await hmacSha256ZkProgram.verifyHmac(key, message);
console.timeEnd('Prove');

// Convert the hash bytes to hex string
const hashHex = proof.publicOutput
  .map((b) => b.toBigInt().toString(16).padStart(2, '0'))
  .join('');
console.log('Final HMAC-SHA256 hash:', hashHex);

console.time('Verify');
await proof.verify();
console.timeEnd('Verify');
