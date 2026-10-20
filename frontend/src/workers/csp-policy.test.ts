import { describe, expect, it } from 'vitest';
import { validateCSPPolicy, isOriginAllowed, createCSPHeaders } from './csp-policy';
import type { CSPPolicyConfig } from './proof.worker.types';

describe('validateCSPPolicy', () => {
  it('returns default config when given an empty config', () => {
    const config = validateCSPPolicy({});
    expect(config).toEqual({
      maxMemoryMB: 256,
      maxExecutionTimeMs: 30000,
      allowedOrigins: ['https://evidence-studio.example.com', 'https://verification.example.com'],
      sandbox: true,
    });
  });

  it('allows overriding valid configuration values', () => {
    const customConfig: Partial<CSPPolicyConfig> = {
      maxMemoryMB: 512,
      maxExecutionTimeMs: 60000,
      allowedOrigins: ['https://custom.example.com'],
      sandbox: false,
    };
    const config = validateCSPPolicy(customConfig);
    expect(config).toEqual({
      maxMemoryMB: 512,
      maxExecutionTimeMs: 60000,
      allowedOrigins: ['https://custom.example.com'],
      sandbox: false,
    });
  });

  it('allows boundary values for maxMemoryMB (1 and 1024)', () => {
    expect(validateCSPPolicy({ maxMemoryMB: 1 }).maxMemoryMB).toBe(1);
    expect(validateCSPPolicy({ maxMemoryMB: 1024 }).maxMemoryMB).toBe(1024);
  });

  it('throws an error when maxMemoryMB is <= 0 or > 1024', () => {
    expect(() => validateCSPPolicy({ maxMemoryMB: 0 })).toThrow(
      'Invalid maxMemoryMB: must be between 1 and 1024',
    );
    expect(() => validateCSPPolicy({ maxMemoryMB: -1 })).toThrow(
      'Invalid maxMemoryMB: must be between 1 and 1024',
    );
    expect(() => validateCSPPolicy({ maxMemoryMB: 1025 })).toThrow(
      'Invalid maxMemoryMB: must be between 1 and 1024',
    );
  });

  it('allows boundary values for maxExecutionTimeMs (1 and 300000)', () => {
    expect(validateCSPPolicy({ maxExecutionTimeMs: 1 }).maxExecutionTimeMs).toBe(1);
    expect(validateCSPPolicy({ maxExecutionTimeMs: 300000 }).maxExecutionTimeMs).toBe(300000);
  });

  it('throws an error when maxExecutionTimeMs is <= 0 or > 300000', () => {
    expect(() => validateCSPPolicy({ maxExecutionTimeMs: 0 })).toThrow(
      'Invalid maxExecutionTimeMs: must be between 1 and 300000',
    );
    expect(() => validateCSPPolicy({ maxExecutionTimeMs: -100 })).toThrow(
      'Invalid maxExecutionTimeMs: must be between 1 and 300000',
    );
    expect(() => validateCSPPolicy({ maxExecutionTimeMs: 300001 })).toThrow(
      'Invalid maxExecutionTimeMs: must be between 1 and 300000',
    );
  });

  it('throws an error when allowedOrigins is not an array', () => {
    expect(() =>
      validateCSPPolicy({ allowedOrigins: 'https://invalid.example.com' as unknown as string[] }),
    ).toThrow('Invalid allowedOrigins: must be an array');
  });
});

describe('isOriginAllowed', () => {
  const baseConfig: CSPPolicyConfig = {
    maxMemoryMB: 256,
    maxExecutionTimeMs: 30000,
    allowedOrigins: [
      'https://evidence-studio.example.com',
      'https://verification.example.com',
      'https://*.sub.example.com',
      '*',
    ],
    sandbox: true,
  };

  it('returns true for origins in allowedOrigins list', () => {
    expect(isOriginAllowed('https://evidence-studio.example.com', baseConfig)).toBe(true);
    expect(isOriginAllowed('https://verification.example.com', baseConfig)).toBe(true);
  });

  it('returns false for disallowed origins not in allowedOrigins list', () => {
    expect(isOriginAllowed('https://malicious.example.com', baseConfig)).toBe(false);
    expect(isOriginAllowed('http://evidence-studio.example.com', baseConfig)).toBe(false);
    expect(isOriginAllowed('https://example.com', baseConfig)).toBe(false);
    expect(isOriginAllowed('', baseConfig)).toBe(false);
  });

  it('handles wildcard entries literally without unintended pattern expansion', () => {
    // Exact match for the literal string '*' returns true when '*' is in allowedOrigins
    expect(isOriginAllowed('*', baseConfig)).toBe(true);
    // Arbitrary origins do not automatically match '*' unless wildcard expansion is implemented
    expect(isOriginAllowed('https://random.org', baseConfig)).toBe(false);

    // Exact match for literal 'https://*.sub.example.com'
    expect(isOriginAllowed('https://*.sub.example.com', baseConfig)).toBe(true);
    // Subdomain does not match literal wildcard string
    expect(isOriginAllowed('https://test.sub.example.com', baseConfig)).toBe(false);
  });

  it('returns false for any origin when allowedOrigins is empty and no wildcard matches', () => {
    const emptyConfig: CSPPolicyConfig = {
      ...baseConfig,
      allowedOrigins: [],
    };
    expect(isOriginAllowed('https://evidence-studio.example.com', emptyConfig)).toBe(false);
    expect(isOriginAllowed('*', emptyConfig)).toBe(false);
  });
});

describe('createCSPHeaders', () => {
  it('returns security headers including Content-Security-Policy when sandbox is true', () => {
    const config: CSPPolicyConfig = {
      maxMemoryMB: 256,
      maxExecutionTimeMs: 30000,
      allowedOrigins: [],
      sandbox: true,
    };
    const headers = createCSPHeaders(config);

    expect(headers).toEqual({
      'Content-Security-Policy':
        "default-src 'none'; script-src 'self'; worker-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
    });
  });

  it('omits Content-Security-Policy header when sandbox is false but retains standard security headers', () => {
    const config: CSPPolicyConfig = {
      maxMemoryMB: 256,
      maxExecutionTimeMs: 30000,
      allowedOrigins: [],
      sandbox: false,
    };
    const headers = createCSPHeaders(config);

    expect(headers).not.toHaveProperty('Content-Security-Policy');
    expect(headers).toEqual({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
    });
  });
});
