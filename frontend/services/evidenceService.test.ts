import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { persistRegistration } from './evidenceService';
import { ApiClientError } from '../services/apiClient';

const fetchMock = vi.fn();

describe('persistRegistration', () => {
  beforeEach(() => {
    fetchMock.reset();
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);
  });

  afterEach(() => {
    vi.unstubGlobal('fetch');
  });

  const payload = {
    txHash: '0xabc123',
    contractId: 'CABCDEF012',
    eventType: 'registered',
    timestamp: 1700000000,
  };

  it('resolves on 201 and sends the payload', async () => {
    fetchMock.mockResolved({
      ok: true,
      status: 201,
      json: async () => ({ id: 'evt_1' }),
    });

    await expect(persistRegistration(payload)).resolves.toEqual({ id: 'evt_1' });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [calledUrl, init] = fetchMock.mock.calls[0];
    expect(String(calledUrl)).toContain('/api/proofs/register');
    expect(init).toMatchObject({ method: 'POST' });
    expect(JSON.parse((init as RequestInit).body as string)).toEqual(payload);
  });

  it('throws a typed ApiClientError on 409', async () => {
    fetchMock.mockResolved({
      ok: false,
      status: 409,
      json: async () => ({
        message: 'Duplicate registration',
        code: 'DUPLICATE_EVENT',
      }),
    });

    const error = await persistRegistration(payload).catch((e) => e);
    expect(error).instanceof(ApiClientError);
    expect((error as ApiClientError).status).toBe(409);
    expect((error as ApiClientError).message).toContain('Duplicate registration');
  });

  it('throws a typed ApiClientError on 500', async () => {
    fetchMock.mockResolved({
      ok: false,
      status: 500,
      json: async () => ({ message: 'Internal server error' }),
    });

    const error = await persistRegistration(payload).catch((e) => e);
    expect(error).instanceof(ApiClientError);
    expect((error as ApiClientError).status).toBe(500);
  });

  it('wraps network failures in a typed error', async () => {
    fetchMock.mockRejected(new TypeError('Failed to fetch'));

    const error = await persistRegistration(payload).catch((e) => e);
    expect(error).instanceof(ApiClientError);
    expect((error as ApiClientError).message).toMatch(/network/i);
  });
});
