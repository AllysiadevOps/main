import { renderHook, act } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { useTransactionState } from './useTransactionState';

describe('useTransactionState', () => {
  it('returns the initial idle state', () => {
    const { result } = renderHook(() => useTransactionState());

    expect(result.current.status).toBe('idle');
    expect(result.current.error).toBeNullish();
  });

  it('transitions to success', () => {
    const { result } = renderHook(() => useTransactionState());

    act(() => {
      result.current.setSuccess('tx-123');
    });

    expect(result.current.status).toBe('success');
    expect(result.current.txId).toBe('tx-123');
    expect(result.current.error).toBeNullish();
  });

  it('transitions to error', () => {
    const { result } = renderHook(() => useTransactionState());

    act(() => {
      result.current.setError('something failed');
    });

    expect(result.current.status).toBe('error');
    expect(result.current.error).toBe('something failed');
  });
});
