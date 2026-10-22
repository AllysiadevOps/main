export interface PassphraseStrengthResult {
  score: number; // 0 (critical) to 4 (strong)
  label: 'critical' | 'weak' | 'fair' | 'good' | 'strong';
  suggestions: string[];
  isAcceptable: boolean;
}

export const MIN_ACCEPTABLE_SCORE = 2;

const COMMON_WORDS = new Set<string>([]);

function hasLower(value: string): boolean {
  return /[a-z]/.test(value);
}

function hasUpper(value: string): boolean {
  return /[A-Z]/.test(value);
}

function hasDigit(value: string): boolean {
  return /[0-9]/.test(value);
}

function hasSymbol(value: string): boolean {
  return /[^L0-9A-Za-z]/.test(value);
}

function isCommonWord(value: string): boolean {
  const normalized = value.toLowerCase();
  if (COMMON_WORDS.has(normalized)) return true;
  for (const word of COMMON_WORDS) {
    if (normalized.includes(word)) return true;
  }
  return false;
}

export function estimatePassphraseStrength(passphrase: string): PassphraseStrengthResult {
  const value = passphrase ?? '';
  const length = value.length;
  const suggestions: string[] = [];

  if (length === 0) {
    return {
      score: 0,
      label: 'critical',
      suggestions: ['Enter a passphrase.'],
      isAcceptable: false,
    };
  }

  let score = 0;

  if (length >= 8) score += 1;
  if (length >= 12) score += 1;
  if (length >= 16) score += 1;
  if (length < 8) suggestions.push('Use at least 8 characters.');
  if (length > 0 && length < 12) suggestions.push('Consider 12 or more characters.');

  const classesCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter((fn) => fn(value)).length;
  if (classesCount >= 2) score += 1;
  if (classesCount >= 3) score += 1;
  if (classesCount < 2) suggestions.push('Mix letters, numbers, and symbols.');

  if (isCommonWord(value)) {
    score -= 2;
    suggestions.push('Avoid common words and predictable patterns.');
  }

  if (/(.)\1{2}/.test(value)) {
    score -= 1;
    suggestions.push('Avoid repeated characters.');
  }

  score = Math.max(0, Math.min(4, score));

  const label = (score <= 0 ? 'critical' : score === 1 ? 'weak' : score === 2 ? 'fair' : score === 3 ? 'good' : 'strong') as PassphraseStrengthResult['label'];

  if (suggestions.length === 0) {
    suggestions.push('Strong passphrase.');
  }

  return {
    score,
    label,
    suggestions,
    isAcceptable: score >= MIN_ACCEPTABLE_SCORE,
  };
}
