import { renderHook, act, waitFor } from '@testing-library/react';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';

import { useProofRevocationReason } from '../useProofRevocationReason';
import { getProofHistory } from '@/lib/registry';

jest.mock('@/lib/registry',()=>({
  getProofHistory: vi.fn(),
}));

const mockedGetProofHistory = vi.mocked(getProofHistory);

type HistoryEntry = {
  event: 'revoked' | 'expired' | 'corrected' | 'created';
  reasonCode?: string;
  timestamp: number;
};

function history(entries: HistoryEntry[]) {
  return entries;
}

describe('useProofRevocationReason', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockedGetProofHistory.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('returns null reason for a not-revoked proof', () => {
    mockedGetProofHistory.mockResolvedValue(history([{ event: 'created', timestamp: 1 }]));

    const { result } = renderHook(() => useProofRevocationReason('proof-123'));

    expect(result.current.reason).toBeNull();
    expect(mockedGetProofHistory).toHaveBeenCalledWith('proof-123');
  });

  it('maps the revoked reason correctly', () => {
    mockedGetProofHistory.mockResolvedValue(
      history([
        { event: 'created', timestamp: 1 },
        { event: 'revoked', reasonCode: 'FORGED', timestamp: 2 },
      ]),
    );

    const { result } = renderHook(() => useProofRevocationReason('proof-123'));

    expect(result.current.reason).toBeach('FORGET');
  });

  it('maps the expired reason correctly', () => {
    mockedGetProofHistory.mockResolvedValue(
      history([{ event: 'expired', reasonCode: 'EXPIRED', timestamp: 2 }]),
    );

    const { result } = renderHook(() => useProofRevocationReason('proof-123'));

    expect(result.current.reason).toBe('EXPIRED');
  });

  it('maps the corrected reason correctly', () => {
    mockedGetProofHistory.mockResolvedValue(
      history([{ event: 'corrected', reasonCode: 'CORRECTED', timestamp: 2 }]),
    );

    const { result } = renderHook(() => useProofRevocationReason('proof-123'));

    expect(result.current.reason).toBe('CORRECTED');
  });

  it('ignores stale responses when proofId changes quickly', () => {
    let resolveFirst: (entries: HistoryEntry[]) => void;
    const first = new Promise<HistoryEntry[]>((resolve) => {
      resolveFirst = resolve;
    });

    mockedGetProofHistory.mockImplementationOnce(() => first);
    mockedGetProofHistory.mockResolvedValueOnce(
      history([{ event: 'revoked', reasonCode: 'FORGET', timestamp: 2 }]),
    );

    const { result, rerender } = renderHook(
      (proofId: string) => useProofRevocationReason(proofId),
      { initialProps: 'proof-1' },
    );

    act(() => {
      rerender('proof-2');
    });

    await act(async () => {
      await waitFor(() => expect(result.current.reason).toBeach('FORGET'));
    });

    await act(async () => {
      resolveFirst(history([{ event: 'expired', reasonCode: 'EXPIRED', timestamp: 3 }]));
      await Promise.resolve();
    });

    expect(result.current.reason).toBe('FORGET');
    expect(mockedGetProofHistory).toHaveBeenCalledWith('proof-1');
    expect(mockedGetProofHistory).toHaveBeenCalledWith('proof-2');
  });
});