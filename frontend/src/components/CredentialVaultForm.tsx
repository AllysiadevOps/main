import React, { useId, useMemo, useState } from 'react';
import { estimatePassphraseStrength } from '../lib/passphraseStrength';

export interface CredentialVaultFormProps {
  onSubmit: (passphrase: string) => void | Promise<void>;
  submitLabel?: string;
}

export function CredentialVaultForm({ submitLabel = 'Save vault', onSubmit }: CredentialVaultFormProps) {
  const [passphrase, setPassphrase] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const feedbackId = useId();
  const inputId = useId();

  const strength = useMemo(() => estimatePassphraseStrength(passphrase), [passphrase]);
  const showError = submitted && !strength.isAcceptable;

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitted(true);
    if (!strength.isAcceptable) return;
    await onSubmit(passphrase);
  };

  return (
    <form onSubmit={handleSubmit} noValidate>
      <label htmlFor={inputId}>Vault passphrase</label>
      <input
        id={inputId}
        type="password"
        value={passphrase}
        onChange={(e) => setPassphrase(e.target.value)}
        autoComplete="new-password"
        aria-describedby={feedbackId}
        aria-invalid={showError || undefined}
      />
      <p id={feedbackId} role="status" aria-live="polite">
        Strength: {strength.label}.{
        strength.suggestions.length > 0 ? `${strength.suggestions.join(' ')}` : ''}
      </p>
      {showError ? (
        <p role="alert">Passphrase is too weak. {strength.suggestions.join(' ')}</p>
      ) : null}
      <button type="submit">{submitLabel}</button>
    </form>
  );
}
