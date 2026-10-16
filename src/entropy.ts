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
 * Checks if a candidate token exceeds entropy thresholds, adapting for character set:
 * - Pure hex strings (0-9, a-f) top out at 4.0 bits, so threshold is 3.2 bits (min length 16).
 * - Base64 and alphanumeric strings use standard 4.3+ bits (min length 12).
 */
export function isHighEntropySecret(
  str: string,
  baseThreshold = 4.5,
): { isSecret: boolean; entropy: number } {
  if (!str || str.length < 12) return { isSecret: false, entropy: 0 };

  const entropy = calculateShannonEntropy(str);
  const isPureHex = /^[0-9a-fA-F]+$/.test(str);

  if (isPureHex) {
    // Hex alphabet max entropy is log2(16) = 4.0 bits. Threshold scaled to 3.2 bits.
    const isSecret = str.length >= 16 && entropy >= 3.2;
    return { isSecret, entropy };
  }

  const isSecret = entropy >= baseThreshold;
  return { isSecret, entropy };
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

  // Git commit SHAs (40 hex chars) or SHA-256 hashes (64 hex chars)
  if (/^[0-9a-f]{40}$/i.test(trimmed) || /^[0-9a-f]{64}$/i.test(trimmed)) {
    return true;
  }

  // Lockfile hashes / pure decimal numbers
  if (/^\d+$/.test(trimmed)) {
    return true;
  }

  // Base64 Data URIs (SVGs, images, fonts, data:image/...)
  if (
    /^(data:image\/|data:application\/|data:font\/)/i.test(trimmed) ||
    trimmed.startsWith("PHN2Zy") ||
    trimmed.startsWith("data:")
  ) {
    return true;
  }

  // Common minified CSS / Webpack chunk artifact identifiers
  if (/^(\.webpack|__webpack_|css-[a-z0-9]+|tw-[a-z0-9]+)/i.test(trimmed)) {
    return true;
  }

  return false;
}
