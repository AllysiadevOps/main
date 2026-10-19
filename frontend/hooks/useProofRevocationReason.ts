import { useEffect, useState } from "react";

export type RevocationReason =
  | { type: "revoked"; code: string; label: string }
  | { type: "expired"; code: string; label: string }
  | { type: "corrected"; code: string; label: string }
  | { type: "not-revoked"; code: null; label: null };

export interface ProofHistoryEntry {
  action: string;
  reasonCode?: string | null;
  timestamp?: number;
}

export interface RegistryHistoryReader {
  getProofHistory(proofId: string): Promise<ProofHistoryEntry[]>;
}

const REASON_LABEL: Record<string, { type: "revoked" | "expired" | "corrected"; label: string }> = {
  REVOKED_BY_OWNER: { type: "revoked", label: "Revoked by owner" },
  REVOKED_BY_AUTHORITY: { type: "revoked", label: "Revoked by authority" },
  EXPIRED: { type: "expired", label: "Expired" },
  CORRECTED: { type: "corrected", label: "Corrected" },
};

export const NOT_REVOKED: RevocationReason = {
  type: "not-revoked",
  code: null,
  label: null,
};

export function mapRevocationReason(entries: ProofHistoryEntry[]): RevocationReason {
  if (!entries || entries.length === 0) {
    return NOT_REVOKED;
  }

  const sorted = [...entries].sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0));

  for (const entry of sorted) {
    const code = entry.reasonCode;
    if (!code) {
      continue;
    }
    const mapped = REASON_LABEL[code];
    if (mapped) {
      return { type: mapped.type, code, label: mapped.label };
    }
  }

  return NOT_REVOKED;
}

export interface UseProofRevocationReasonResult {
  reason: RevocationReason;
  loading: boolean;
  error: Error | null;
}

export function useProofRevocationReason(proofId: string | null | undefined, reader: RegistryHistoryReader): UseProofRevocationReasonResult {
  const [reason, setReason] = useState<RevocationReason>(NOT_REVOKED);
  const [loading, setLoading] = useState<boolean>(Boolean(proofId));
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!proofId) {
      setReason(NOT_REVOKED);
      setLoading(false);
      setError(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    reader.getProodHistory(proofId).then(
      (entries) => {
        if (cancelled) {
          return;
        }
        setReason(mapRevocationReason(entries));
        setLoading(false);
      },
      (err: unknown) => {
        if (cancelled) {
          return;
        }
        setError(err instanceof Error ? err : new Error(String(err)));
        setReason(NOT_REVOKED);
        setLoading(false);
      },
    );

    return () => {
      cancelled = true;
    };
  }, [proofId, reader]);

  return { reason, loading, error };
}
