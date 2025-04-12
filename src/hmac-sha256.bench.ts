import { ZkProgram, Bytes } from 'o1js';
import { HMAC_SHA256 } from './hmac-sha256.js';

async function measureConstraints(
  key: Bytes,
  message: Bytes,
  keySize: number,
  messageSize: number
): Promise<{ constraints: number; time: number }> {
  const startTime = performance.now();
  
  const program = ZkProgram({
    name: 'hmac-sha256-verify',
    publicOutput: Bytes(32),
    methods: {
      verifyHmac: {
        privateInputs: [
          Bytes(keySize),
          Bytes(messageSize),
        ],
        async method(k: Bytes, m: Bytes) {
          const hash = HMAC_SHA256.compute(k, m);
          return { publicOutput: hash };
        },
      },
    },
  });

  const { verifyHmac } = await program.analyzeMethods();
  const summary = verifyHmac.summary();
  const endTime = performance.now();

  return {
    constraints: summary['Total rows'],
    time: (endTime - startTime) / 1000
  };
}

async function runBenchmarks() {
  console.log('| Test Vector | Constraints | Message Length (n) | Key Length (k) | Execution Time (s) |');
  console.log('|-------------|-------------|-------------------|----------------|-------------------|');

  // Test Case 1
  {
    const key = Bytes.fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const message = Bytes.fromString('Hi There');
    const result = await measureConstraints(key, message, 20, 8);
    console.log(`| 1           | ${result.constraints.toLocaleString().padEnd(10)} | 8                 | 20             | ${result.time.toFixed(3).padEnd(14)} |`);
  }

  // Test Case 2
  {
    const key = Bytes.fromString('Jefe');
    const message = Bytes.fromString('what do ya want for nothing?');
    const result = await measureConstraints(key, message, 4, 28);
    console.log(`| 2           | ${result.constraints.toLocaleString().padEnd(10)} | 28                | 4              | ${result.time.toFixed(3).padEnd(14)} |`);
  }

  // Test Case 3
  {
    const key = Bytes.fromHex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const message = Bytes.fromHex('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
    const result = await measureConstraints(key, message, 20, 50);
    console.log(`| 3           | ${result.constraints.toLocaleString().padEnd(10)} | 50                | 20             | ${result.time.toFixed(3).padEnd(14)} |`);
  }

  // Test Case 4
  {
    const key = Bytes.fromHex('0102030405060708090a0b0c0d0e0f10111213141516171819');
    const message = Bytes.fromHex('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd');
    const result = await measureConstraints(key, message, 25, 50);
    console.log(`| 4           | ${result.constraints.toLocaleString().padEnd(10)} | 50                | 25             | ${result.time.toFixed(3).padEnd(14)} |`);
  }

  // Test Case 5
  {
    const key = Bytes.fromHex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c');
    const message = Bytes.fromString('Test With Truncation');
    const result = await measureConstraints(key, message, 20, 20);
    console.log(`| 5           | ${result.constraints.toLocaleString().padEnd(10)} | 20                | 20             | ${result.time.toFixed(3).padEnd(14)} |`);
  }

  // Test Case 6
  {
    const key = Bytes.fromHex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const message = Bytes.fromString('Test Using Larger Than Block-Size Key - Hash Key First');
    const result = await measureConstraints(key, message, 131, 54);
    console.log(`| 6           | ${result.constraints.toLocaleString().padEnd(10)} | 54                | 131            | ${result.time.toFixed(3).padEnd(14)} |`);
  }

  // Test Case 7
  {
    const key = Bytes.fromHex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const message = Bytes.fromString('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.');
    const result = await measureConstraints(key, message, 131, 152);
    console.log(`| 7           | ${result.constraints.toLocaleString().padEnd(10)} | 152               | 131            | ${result.time.toFixed(3).padEnd(14)} |`);
  }

  console.log('\n_Tests performed on ' + process.platform + ' with Node.js ' + process.version + '_');
}

runBenchmarks().catch(console.error); 