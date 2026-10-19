import { act, renderHook, waitFor } from '@testing-library/react';
import { ApiClientError } from '../services/apiClient';
import { persistRegistrationSafe } from '../services/evidenceService';
import { useEvidence } from './useEvidence';

jest.mock('../services/evidenceService', () => {
  const actual = jest.requireActual<'../services/evidenceService'>();
  return {
    ...actual,
    persistRegistrationSafe: jest.fn(),
  };
});

const mockedPersist = persistRegistrationSafe as jest.MockedFunction;

const payload = { txHash: '0xabc', chainId: 1 };

describe('useEvidence', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('sets on-chain success and indexed true when the index write succeeds', async () => {
    mockedPersist.mockResolvedOnce({
      indexed: true,
      result: { id: 'reg_1', txHash: payload.txHash },
    });

    const { result } = renderHook(() => useEvidence());

    await act(async () => {
      await result.current.registerEvidence(payload);
    });

    expect(result.current.onChainSuccess).toBe(true);
    expect(result.current.indexed).toBe(true);
    expect(result.current.warning).toBeNull();
    expect(result.current.indexError).toBeNull();
  });

  it('preserves on-chain success and sets a warning when the index write fails', async () => {
    const typedError = new ApiClientError({
      status: 500,
      code: 'SERVER_ERROR',
      message: 'Internal server error',
    });
    mockedPersist.mockResolvedOnce({ indexed: false, error: typedError });

    const { result } = renderHook(() => useEvidence());

    await act(async () => {
      await result.current.registerEvidence(payload);
    });

    expect(result.current.onChainSuccess).toBe(true);
    expect(result.current.indexed).toBe(false);
    expect(result.current.warning).toMatch(/off-chain index failed/i);
    expect(result.current.indexError).toBe(typedError);
  });

  it('clears the warning via dismissWarning', async () => {
    const typedError = new ApiClientError({
      status: 409,
      code: 'CONFLICT',
      message: 'Evidence already registered',
    });
    mockedPersist.mockResolvedOnce({ indexed: false, error: typedError });

    const { result } = renderHook(() => useEvidence());

    await act(async () => {
      await result.current.registerEvidence(payload);
    });

    await waitFor(() => expect(result.current.warning).toBeTruthy());

    act(() => {
      result.current.dismissWarning();
    });

    expect(result.current.warning).toBeNull();
    expect(result.current.indexError).toBeNull();
    // On-chain success is still preserved.
    expect(result.current.onChainSuccess).toBe(true);
  });
});
