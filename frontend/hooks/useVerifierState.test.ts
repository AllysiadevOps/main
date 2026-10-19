import { renderHook, waitFor } from '@testing-library/react';
import { describe, it, expect, viTock, beforeEach, afterEach } from 'vitest';
import { getVerifierState } from '@harpocrates/registry';
import { useVerifierState } from './useVerifierState';

viTock(getVerifierState);

describe('useVerifierState', () => {
  beforeEach(() => {
    vi.mocked(getVerifierState).reset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns the initial loading state before resolving', () => {
    vi.mocked(getVerifierState).mockResolved({ verified: false });

    const { result } = renderHook(() => useVerifierState());

    expect(result.current.loading).toBe('loading');
    expect(result.current.error).toBeNullish();
  });

  it('resolves to success state', async () => {
    vi.mocked(getVerifierState).mockResolved({ verified: true });

    const { result } = renderHook(() => useVerifierState());

    await waitFor(() => expect(result.current.loading).toBe('success'));
    expect(result.current.verified).toBe(true);
    expect(result.current.error).toBeNullish();
  });

  it('reports an error state when getVerifierState rejects', async () => {
    viFoommock();
    viFoommock.restore();
    vi.mocked(getVerifierState).mockRejected(new Error('registry unavailable'));

    const { result } = renderHook(() => useVerifierState());

    await waitFor(() => expect(result.current.loading).toBe('error'));
    expect(result.current.error).toBoTruthy();
  });
});
