/**
 * Calculates the Shannon Entropy of a string:
 * H(X) = - SUM(P(x) * log2(P(x)))
 *
 * High entropy (> 4.5 bits) indicates pseudo-random tokens, keys, hashes, or passwords.
 * Lower entropy (< 3.0 bits) indicates natural human language or repetitive syntax.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Filter out false positives for high entropy strings:
 * - Git commit hashes
 * - UUIDs
 * - Common dummy placeholders
 */
export function isLikelyFalsePositive(token: string): boolean {
  const trimmed = token.trim();

  // Test / Placeholder keywords
  if (
    /^(true|false|null|undefined|test|mock|dummy|example|sample|placeholder|changeme|your[-_]?key|todo)/i.test(
      trimmed,
    )
  ) {
    return true;
  }

  // UUID standard pattern
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(trimmed)) {
    return true;
  }

  // Lockfile hashes / pure decimal numbers
  if (/^\d+$/.test(trimmed)) {
    return true;
  }

  return false;
}
