import { estimatePassphraseStrength } from './passphraseStrength';

export interface CredentialMaterial {
  id: string;
  username: string;
  secret: string;
}

export interface EncryptedVault {
  ciphertext: string;
  iv: string;
}

export class WeakPassphraseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WeakPassphraseError';
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function assertStrongPassphrase(passphrase: string): void {
  const result = estimatePassphraseStrength(passphrase);
  if (!result.isAcceptable) {
    throw new WeakPassphraseError(
      result.suggestions.join(' ') || 'Passphrase is too weak.',
    );
  }
}

export async function encryptCredentials(
  material: CredentialMaterial[],
  passphrase: string,
): Promise<EncryptedVault> {
  assertStrongPassphrase(passphrase);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, iv);
  const encoder = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(JSON.stringify(material)),
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv),
  };
}

export async function decryptCredentials(
  vault: EncryptedVault,
  passphrase: string,
): Promise<CredentialMaterial[]> {
  const iv = base64ToBytes(vault.iv);
  const key = await deriveKey(passphrase, iv);
  const ciphertext = base64ToBytes(vault.ciphertext);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext,
  );
  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext)) as CredentialMaterial[];
}
