import { ZkProgram, Bytes } from 'o1js';
import { HMAC_SHA256 } from '../src/hmac-sha256.js';

export let hmacSha256ZkProgram = ZkProgram({
  name: 'hmac-sha256-verify',
  publicOutput: Bytes(32), // HMAC-SHA256 Hash (256 bits / 32 bytes)
  methods: {
    verifyHmac: {
      privateInputs: [
        Bytes(64), // Key (512 bits / 64 bytes)
        Bytes(64), // Message (512 bits / 64 bytes)
      ],

      async method(key: Bytes, message: Bytes) {
        const hash = HMAC_SHA256.compute(key, message);
        return { publicOutput: hash };
      },
    },
  },
});

const key = Bytes(64).fromString(
  '4q72JHgX89z3BkFMt6cwQxL1rD28jpN5UfVhIZYPbCSeuGovRaWmA0sD9ECtX7Jf'
);
const message = Bytes(64).fromString(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
);

let { verifyHmac } = await hmacSha256ZkProgram.analyzeMethods();

console.log(verifyHmac.summary());

console.time('Compile');
const forceRecompileEnabled = false;
await hmacSha256ZkProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('Compile');

console.time('Prove');
let { proof } = await hmacSha256ZkProgram.verifyHmac(key, message);
console.timeEnd('Prove');

const hashHex = proof.publicOutput.toHex();
console.log('Final HMAC-SHA256 hash:', hashHex);

console.time('Verify');
await proof.verify();
console.timeEnd('Verify');
