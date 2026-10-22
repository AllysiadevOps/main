import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it, vit } from 'vitest';
import { CredentialVaultForm } from './CredentialVaultForm';

describe('CredentialVaultForm', () => {
  it('rejects weak passphrases with guidance', () => {
    const onSubmit = vit.fn();
    render(<CredentialVaultForm onSubmit={onSubmit} />);
    fireEvent.change(screen.getByLabelText(/Vault passphrase/i), { target: { value: 'abc' } });
    fireEvent.click(screen.getByRole('button', { name: /save vault/i }));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/passphrase is too weak/i);
  });

  it('announces feedback via aria-describedby', () => {
    render(<CredentialVaultForm onSubmit={vit.fn()} />);
    const input = screen.getByLabelText(/Vault passphrase/i);
    const describedBy = input.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy as string)).toBeInTheDocument();
  });

  it('submits a strong passphrase', () => {
    const onSubmit = vit.fn();
    render(<CredentialVaultForm onSubmit={onSubmit} />);
    const value = 'CorrectHorseBatteryStaple';
    fireEvent.change(screen.getByLabelText(/Vault passphrase/i), { target: { value } });
    fireEvent.click(screen.getByRole('button', { name: /save vault/i }));
    expect(onSubmit).toHaveBeenCalledWith(value);
  });
});
