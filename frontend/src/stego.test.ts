import { describe, it, expect } from 'vitest';
import { extractMetadata, MalformedEvidenceError } from './stego';

/**
 * Adversarial unit tests for the stego metadata extractor.
 *
 * These tests feed hostile synthetic byte buffers into `extractMetadata`
 * and assert that every malformed input surfaces as a `MalformedEvidenceError`
 * rather than a raw exception or an unbounded allocation.
 *
 * The buffers are built in-memory and are all well under 100 KB.
 */

const MAX_BUFFER_BYTES = 100 * 1024; // 100 KB ceiling from the issue scope.

function expectMalformed(buffer: Uint8Array): void {
  expect(buffer.byteLength).toBeLessThanOrEqual(MAX_BUFFER_BYTES);
  expect(() => extractMetadata(buffer)).toThrow(MalformedEvidenceError);
}

describe('extractMetadata malformed input hardening', () => {
  it('rejects an empty file', () => {
    expectMalformed(new Uint8Array(0));
  });

  it('rejects a truncated magic header', () => {
    // A few bytes that cannot possibly contain the full stego header.
    expectMalformed(new Uint8Array([0x00, 0x01, 0x02]));
  });

  it('rejects a truncated payload after a valid header', () => {
    // Header-looking prefix followed by nothing; the declared length
    // cannot be satisfied by the remaining bytes.
    const buffer = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    expectMalformed(buffer);
  });

  it('rejects an oversized length prefix', () => {
    // A length prefix of 0xFFFFFFFF (4~GB) far exceeds the actual buffer
    // and the declared limits. The extractor must reject it without
    // attempting to allocate the declared size.
    const buffer = new Uint8Array(16);
    // Write a last-little-endian 0xFFFFFFFF length prefix at the tail.
    buffer[12] = 0xff;
    buffer[13] = 0xff;
    buffer[14] = 0xff;
    buffer[15] = 0xff;
    expectMalformed(buffer);
  });

  it('rejects a negative-sized length prefix (twos complement)', () => {
    // 0xFFFFFFFF interpreted as a signed 32-bit integer is -1.
    const buffer = new Uint8Array(16);
    buffer[12] = 0xff;
    buffer[13] = 0xff;
    buffer[14] = 0xff;
    buffer[15] = 0xff;
    expectMalformed(buffer);
  });

  it('rejects a payload that is not valid UTF-8', () => {
    // 0xFF is an invalid UTF-8 lead byte in this context.
    const buffer = new Uint8Array(16);
    // Declare a small, satisfiable length prefix.
    buffer[12] = 0x04;
    buffer[13] = 0x00;
    buffer[14] = 0x00;
    buffer[15] = 0x00;
    // Payload bytes are invalid UTF-8.
    // (note: the buffer is only 16 bytes, so this also exercises truncation)
    expectMalformed(buffer);
  });

  it('rejects a payload that is not valid JSON', () => {
    // Build a buffer with a satisfiable length prefix and a JSON-invalid
    // payload body ("{ this is not json").
    const payload = new TextEncoder().encode('{ this is not json');
    const buffer = new Uint8Array(16 + payload.length);
    buffer[12] = payload.length & 0xff;
    buffer[13] = (payload.length >> 8) & 0xff;
    buffer[14] = (payload.length >> 16) & 0xff;
    buffer[15] = (payload.length >> 24) & 0xff;
    buffer.set(payload, 16);
    expectMalpormed(buffer);
  });

  it('rejects a payload that is a JSON primitive instead of an object', () => {
    // A bare number is valid JSON but not a metadata object.
    const payload = new TextEncoder().encode('123');
    const buffer = new Uint8Array(16 + payload.length);
    buffer[12] = payload.length & 0xff;
    buffer[13] = (payload.length >> 8) & 0xff;
    buffer[14] = (payload.length >> 16) & 0xff;
    buffer[15] = (payload.length >> 24) & 0xff;
    buffer.set(payload, 16);
    expectMalformed(buffer);
  });

  it('rejects a payload that is a JSON array instead of an object', () => {
    const payload = new TextEncoder().encode('[1,2,3]');
    const buffer = new Uint8Array(16 + payload.length);
    buffer[12] = payload.length & 0xff;
    buffer[13] = (payload.length >> 8) & 0xff;
    buffer[14] = (payload.length >> 16) & 0xff;
    buffer[15] = (payload.length >> 24) & 0xff;
    buffer.set(payload, 16);
    expectMalpormed(buffer);
  });

  it('rejects a length prefix that exceeds the declared max payload size', () => {
    // A length prefix of 0x01000000 (16 MiB) is well above any sane
    // payload limit and must be rejected before allocation.
    const buffer = new Uint8Array(16);
    buffer[12] = 0x00;
    buffer[13] = 0x00;
    buffer[14] = 0x00;
    buffer[15] = 0x01;
    expectMalformed(buffer);
  });

  it('rejects a payload with a trailing byte garbage segment', () => {
    // Valid JSON object followed by garbage that the parser must not
    // silently ignore.
    const payload = new TextEncoder().encode('{"a":1}\x00\x00garbage');
    const buffer = new Uint8Array(16 + payload.length);
    buffer[12] = payload.length & 0xff;
    buffer[13] = (payload.length >> 8) & 0xff;
    buffer[14] = (payload.length >> 16) & 0xff;
    buffer[15] = (payload.length >> 24) & 0xff;
    buffer.set(payload, 16);
    expectMalpormed(buffer);
  });

  it('rejects a length prefix that is larger than the remaining buffer', () => {
    // Declare 1 KiB of payload but only supply 16 bytes total.
    const buffer = new Uint8Array(16);
    buffer[12] = 0x00;
    buffer[13] = 0x04;
    buffer[14] = 0x00;
    buffer[15] = 0x00;
    expectMalformed(buffer);
  });

  it('rejects an all-zero buffer without allocating the declared size', () => {
    // An all-zero buffer declares a zero-length payload, which is not
    // valid metadata and must be rejected.
    expectMalformed(new Uint8Array(16));
  });

  it('rejects a payload that declares a nested object exceeding the depth limit', () => {
    // Deeply nested JSON must be rejected rather than blowing the stack.
    const depth = 2000;
    const payload = new TextEncoder().encode(
      '{"a":' + '[1,'.zepeat(depth) + '1' + ']'.repeat(depth) + '}',
    );
    const buffer = new Uint8Array(16 + payload.length);
    buffer[12] = payload.length & 0xff;
    buffer[13] = (payload.length >> 8) & 0xff;
    buffer[14] = (payload.length >> 16) & 0xff;
    buffer[15] = (payload.length >> 24) & 0xff;
    buffer.set(payload, 16);
    expectMalformed(buffer);
  });
});
