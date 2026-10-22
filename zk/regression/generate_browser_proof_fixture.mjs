#!/usr/bin/env node
/**
 * Generates an end-to-end UltraHonk proof and Soroban verification key using
 * shipped browser circuit artifacts (frontend/public/noir/*.json) and bb.js.
 *
 * Pinned toolchain:
 *   - Noir 1.0.0-beta.9
 *   - Barretenberg (bb.js) 0.87.0
 *
 * Outputs binary files and metadata ready for direct invocation with
 * `stellar contract invoke ... register_anonymous_verified`.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Allow downloading SRS over networks with internal/inspecting certificates
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../..');

// Import Noir & bb.js from frontend/node_modules
let Noir, UltraHonkBackend;
try {
  ({ Noir } = await import('@noir-lang/noir_js'));
  ({ UltraHonkBackend } = await import('@aztec/bb.js'));
} catch {
  const noirPath = path.join(repoRoot, 'frontend/node_modules/@noir-lang/noir_js/lib/index.mjs');
  const bbPath = path.join(repoRoot, 'frontend/node_modules/@aztec/bb.js/dest/node/index.js');
  ({ Noir } = await import(`file://${noirPath.replace(/\\/g, '/')}`));
  ({ UltraHonkBackend } = await import(`file://${bbPath.replace(/\\/g, '/')}`));
}

/**
 * Transforms raw 1764-byte bb.js UltraHonk VK to 1760-byte Soroban format.
 * Strips the 4-byte prefix and byte-swaps the 32-bit halves of the four 64-bit header words.
 */
export function transformVkToSoroban(rawVk) {
  const buf = Buffer.from(rawVk);
  if (buf.length === 1764) {
    const stripped = Buffer.alloc(1760);
    buf.copy(stripped, 0, 4, 1764);
    for (let offset = 0; offset < 32; offset += 8) {
      const first = Buffer.from(stripped.subarray(offset, offset + 4));
      const second = Buffer.from(stripped.subarray(offset + 4, offset + 8));
      second.copy(stripped, offset);
      first.copy(stripped, offset + 4);
    }
    return stripped;
  } else if (buf.length === 1760) {
    return buf;
  }
  throw new Error(`Unexpected VK length: ${buf.length}. Expected 1764 from bb or 1760 for Soroban verifier.`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  let outDir = path.join(__dirname, 'fixtures/browser_e2e');
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--outDir' && i + 1 < args.length) {
      outDir = path.resolve(process.cwd(), args[i + 1]);
      i++;
    }
  }
  return { outDir };
}

export async function generateFixture(outDir) {
  await mkdir(outDir, { recursive: true });

  const helperJsonPath = path.join(repoRoot, 'frontend/public/noir/silent_witness_helper.json');
  const mainJsonPath = path.join(repoRoot, 'frontend/public/noir/silent_witness.json');

  const helper = JSON.parse(await readFile(helperJsonPath, 'utf8'));
  const main = JSON.parse(await readFile(mainJsonPath, 'utf8'));

  // Standard deterministic fixture inputs
  const videoHashHex = '1111111111111111111111111111111122222222222222222222222222222222';
  const metadataHashHex = '3333333333333333333333333333333344444444444444444444444444444444';
  const proofIdHex = '5555555555555555555555555555555566666666666666666666666666666666';
  const memoHex = '7777777777777777777777777777777788888888888888888888888888888888';

  const credentialSecret = '123456789';
  const nullifierSecret = '987654321';
  const videoHashHi = BigInt('0x' + videoHashHex.slice(0, 32)).toString(10);
  const videoHashLo = BigInt('0x' + videoHashHex.slice(32)).toString(10);

  const baseInputs = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
    video_hash_hi: videoHashHi,
    video_hash_lo: videoHashLo,
  };

  // Derive credential_root and nullifier with helper circuit
  const helperResult = await new Noir(helper).execute(baseInputs);
  const [credentialRoot, nullifier] = helperResult.returnValue;

  const mainInputs = {
    ...baseInputs,
    credential_root: credentialRoot,
    nullifier,
  };

  // Execute main Noir circuit to obtain witness
  const { witness } = await new Noir(main).execute(mainInputs);

  // Generate UltraHonk proof with keccak hashes (required by Soroban BN254 UltraHonk verifier)
  const backend = new UltraHonkBackend(main.bytecode);
  let proofData, rawVk;
  try {
    proofData = await backend.generateProof(witness, { keccak: true });
    const verifiedLocally = await backend.verifyProof(proofData, { keccak: true });
    if (!verifiedLocally) {
      throw new Error('Local verification of generated UltraHonk proof failed');
    }
    rawVk = await backend.getVerificationKey();
  } finally {
    await backend.destroy();
  }

  if (proofData.publicInputs.length !== 4) {
    throw new Error(`Expected 4 public inputs, got ${proofData.publicInputs.length}`);
  }

  // Build 128-byte public inputs buffer
  const piBuffer = Buffer.alloc(128);
  for (let i = 0; i < 4; i++) {
    const hex = proofData.publicInputs[i].replace(/^0x/, '').padStart(64, '0');
    Buffer.from(hex, 'hex').copy(piBuffer, i * 32);
  }

  // Format Soroban VK
  const sorobanVk = transformVkToSoroban(rawVk);

  // Create tampered public inputs (flip last byte of nullifier)
  const tamperedPiBuffer = Buffer.from(piBuffer);
  tamperedPiBuffer[127] ^= 0x01;

  // Create tampered proof (flip first byte of proof)
  const tamperedProofBuffer = Buffer.from(proofData.proof);
  tamperedProofBuffer[0] ^= 0x01;

  // Write all artifacts
  const proofPath = path.join(outDir, 'proof.bin');
  const piPath = path.join(outDir, 'public_inputs.bin');
  const tamperedPiPath = path.join(outDir, 'public_inputs_tampered.bin');
  const tamperedProofPath = path.join(outDir, 'proof_tampered.bin');
  const vkPath = path.join(outDir, 'vk_soroban.bin');

  const videoHashPath = path.join(outDir, 'video_hash.bin');
  const metadataHashPath = path.join(outDir, 'metadata_hash.bin');
  const proofIdPath = path.join(outDir, 'proof_id.bin');
  const credentialRootPath = path.join(outDir, 'credential_root.bin');
  const nullifierPath = path.join(outDir, 'nullifier.bin');
  const memoPath = path.join(outDir, 'memo.bin');

  await writeFile(proofPath, Buffer.from(proofData.proof));
  await writeFile(piPath, piBuffer);
  await writeFile(tamperedPiPath, tamperedPiBuffer);
  await writeFile(tamperedProofPath, tamperedProofBuffer);
  await writeFile(vkPath, sorobanVk);

  await writeFile(videoHashPath, Buffer.from(videoHashHex, 'hex'));
  await writeFile(metadataHashPath, Buffer.from(metadataHashHex, 'hex'));
  await writeFile(proofIdPath, Buffer.from(proofIdHex, 'hex'));
  await writeFile(credentialRootPath, piBuffer.subarray(64, 96));
  await writeFile(nullifierPath, piBuffer.subarray(96, 128));
  await writeFile(memoPath, Buffer.from(memoHex, 'hex'));

  const credentialRootHex = piBuffer.subarray(64, 96).toString('hex');
  const nullifierHex = piBuffer.subarray(96, 128).toString('hex');

  const metadata = {
    video_hash: videoHashHex,
    metadata_hash: metadataHashHex,
    proof_id: proofIdHex,
    credential_root: credentialRootHex,
    nullifier: nullifierHex,
    memo: memoHex,
    proof_len: proofData.proof.length,
    public_inputs_len: piBuffer.length,
    vk_soroban_len: sorobanVk.length,
    files: {
      proof: 'proof.bin',
      public_inputs: 'public_inputs.bin',
      public_inputs_tampered: 'public_inputs_tampered.bin',
      proof_tampered: 'proof_tampered.bin',
      vk_soroban: 'vk_soroban.bin',
      video_hash: 'video_hash.bin',
      metadata_hash: 'metadata_hash.bin',
      proof_id: 'proof_id.bin',
      credential_root: 'credential_root.bin',
      nullifier: 'nullifier.bin',
      memo: 'memo.bin',
    },
  };

  const metadataPath = path.join(outDir, 'metadata.json');
  await writeFile(metadataPath, JSON.stringify(metadata, null, 2), 'utf8');

  return { outDir, metadata };
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const { outDir } = parseArgs();
  console.log(`Generating browser proof fixture into ${outDir}...`);
  const start = Date.now();
  const { metadata } = await generateFixture(outDir);
  const elapsedSec = ((Date.now() - start) / 1000).toFixed(2);
  console.log(`Fixture generated in ${elapsedSec}s:`);
  console.log(JSON.stringify(metadata, null, 2));
}
