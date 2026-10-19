import { useCallback, useState } from 'react';
import {
  persistRegistrationSafe,
  type RegistrationPayload,
  type RegistrationResult,
} from '../services/evidenceService';
import type { ApiClientError } from '../services/apiClient';

export interface EvidenceState {
  /** True once the on-chain registration succeeded. */
  onChainSuccess: boolean;
  /** True when the off-chain index write succeeded. */
  indexed: boolean;
  /** Non-blocking warning message when the off-chain index failed. */
  warning: string | null;
  /** Typed error from the off-chain index write, if any. */
  indexError: ApiClientError | null;
  /** Result of the off-chain write, if successful. */
  result: RegistrationResult | null;
}

export interface UseEvidenceResult extends EvidenceState {
  /** Records an on-chain success and persists to the off-chain index. */
  registerEvidence: (payload: RegistrationPayload) => Promise<void>;
  /** Clears the warning and any stored error. */
  dismissWarning: () => void;
}

const INITIAL_STATE: EvidenceState = {
  onChainSuccess: false,
  indexed: false,
  warning: null,
  indexError: null,
  result: null,
};

export function useEvidence(): UseEvidenceResult {
  const [state, setState] = useState<EvidenceState>(INITIAL_STATE);

  const registerEvidence = useCallback(async (payload: RegistrationPayload) => {
    // The on-chain transaction has already succeeded by the time this is called.
    // Keep that success state even if the off-chain index write fails.
    setState((prev) => ({
      ...prev,
      onChainSuccess: true,
      warning: null,
      indexError: null,
    }));

    const outcome = await persistRegistrationSafe(payload);

    if (outcome.indexed) {
      setState((prev) => ({
        ...prev,
        onChainSuccess: true,
        indexed: true,
        warning: null,
        indexError: null,
        result: outcome.result ?? null,
      }));
      return;
    }

    const error = outcome.error ?? null;
    setState((prev) => ({
      ...prev,
      // Preserve the on-chain success state.
      onChainSuccess: true,
      indexed: false,
      warning:
        'Your evidence was registered on-chain, but the off-chain index failed to record it. ' +
        'The evidence may not appear in search results until this is resolved.',
      indexError: error,
      result: null,
    }));
  }, []);

  const dismissWarning = useCallback(() => {
    setState((prev) => ({ ...prev, warning: null, indexError: null }));
  }, []);

  return {
    ...state,
    registerEvidence,
    dismissWarning,
  };
}

export default useEvidence;
