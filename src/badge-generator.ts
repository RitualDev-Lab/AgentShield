/**
 * AgentShield Sponsor & Security Audit Verification Badge Generator
 * Provides dynamic SVG badges, cryptographic audit verification,
 * and shield shields.io / GitHub markdown badges for tools featured on DevShelf.
 */
import { createHmac } from "node:crypto";
import { AGENTSHIELD_VERSION } from "./version.js";

export type AuditBadgeTier = "verified" | "sponsor" | "enterprise";

export interface SponsorAuditRecord {
  toolName: string;
  repoUrl: string;
  tier: AuditBadgeTier;
  verifiedAt: string;
  auditScore: number;
  zeroLeakVerified: boolean;
  tamperProofHash: string;
}

export interface BadgeOptions {
  tier?: AuditBadgeTier;
  label?: string;
  message?: string;
  color?: string;
  style?: "flat" | "flat-square" | "gradient";
  logo?: boolean;
}

export class VerifiedBadgeGenerator {
  private static readonly BADGE_SECRET =
    process.env.AGENTSHIELD_BADGE_SECRET || "agentshield_verified_salt_2026";

  /**
   * Generates a tamper-evident verification hash for an audited tool
   */
  public static signAuditRecord(toolName: string, repoUrl: string, tier: AuditBadgeTier): string {
    const payload = `${toolName.toLowerCase().trim()}|${repoUrl.toLowerCase().trim()}|${tier}`;
    return createHmac("sha256", this.BADGE_SECRET).update(payload).digest("hex").slice(0, 16);
  }

  /**
   * Verifies if a given audit hash is authentic
   */
  public static verifyAuditRecord(
    toolName: string,
    repoUrl: string,
    tier: AuditBadgeTier,
    providedHash: string,
  ): boolean {
    const expected = this.signAuditRecord(toolName, repoUrl, tier);
    return expected.toLowerCase() === providedHash.toLowerCase();
  }

  /**
   * Generates a crisp SVG badge for embedding in README.md or documentation
   */
  public static generateSvgBadge(toolName: string, options: BadgeOptions = {}): string {
    const tier = options.tier || "verified";
    const label = options.label || "Secured by";
    let message = options.message;

    if (!message) {
      if (tier === "sponsor") {
        message = "AgentShield ★ Sponsor";
      } else if (tier === "enterprise") {
        message = "AgentShield Enterprise";
      } else {
        message = "AgentShield Zero-Leak";
      }
    }

    const primaryColor = tier === "sponsor" ? "#ec4899" : tier === "enterprise" ? "#06b6d4" : "#8b5cf6";
    const leftText = label.toUpperCase();
    const rightText = message;

    // Approximate character widths for crisp layout
    const leftWidth = Math.max(leftText.length * 7 + 16, 75);
    const rightWidth = Math.max(rightText.length * 7 + 22, 110);
    const totalWidth = leftWidth + rightWidth;
    const height = 24;

    const leftCenter = leftWidth / 2;
    const rightCenter = leftWidth + rightWidth / 2;

    return `
<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${height}" viewBox="0 0 ${totalWidth} ${height}" role="img" aria-label="${leftText}: ${rightText}">
  <title>${leftText}: ${rightText}</title>
  <linearGradient id="glow" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" stop-color="${primaryColor}" stop-opacity="0.9"/>
    <stop offset="100%" stop-color="${tier === "sponsor" ? "#be185d" : "#6d28d9"}" stop-opacity="1"/>
  </linearGradient>
  <clipPath id="round-corner">
    <rect width="${totalWidth}" height="${height}" rx="5" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#round-corner)">
    <!-- Left background -->
    <rect width="${leftWidth}" height="${height}" fill="#111827"/>
    <!-- Right background -->
    <rect x="${leftWidth}" width="${rightWidth}" height="${height}" fill="url(#glow)"/>
    <!-- Subtle overlay border -->
    <rect width="${totalWidth}" height="${height}" fill="none" stroke="rgba(255,255,255,0.12)" stroke-width="1"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="10.5" font-weight="600" letter-spacing="0.4">
    <!-- Left text -->
    <text x="${leftCenter}" y="16.5" fill="#9ca3af" text-shadow="0 1px 2px rgba(0,0,0,0.6)">${leftText}</text>
    <!-- Right text with shield icon -->
    <text x="${rightCenter}" y="16.5" fill="#ffffff" font-weight="700">🛡️ ${rightText}</text>
  </g>
</svg>`.trim();
  }

  /**
   * Returns Markdown snippets for GitHub README.md integration
   */
  public static getMarkdownSnippet(
    toolName: string,
    canonicalDomain: string = "https://agentshield.ritualdev.in",
    tier: AuditBadgeTier = "verified",
  ): { markdown: string; html: string; shieldsIoBadgeUrl: string } {
    const slug = encodeURIComponent(toolName.toLowerCase().replace(/\s+/g, "-"));
    const badgeSvgUrl = `${canonicalDomain}/api/v1/badges/${slug}.svg?tier=${tier}`;
    const auditVerifyUrl = `${canonicalDomain}/verify/${slug}`;

    const label = "Secured by";
    const status = tier === "sponsor" ? "AgentShield ★ Sponsor" : "AgentShield Zero--Leak";
    const color = tier === "sponsor" ? "ec4899" : "8b5cf6";
    const shieldsIoBadgeUrl = `https://img.shields.io/badge/${encodeURIComponent(label)}-${encodeURIComponent(status)}-${color}?logo=shield&logoColor=white&style=flat-square`;

    const markdown = `[![Secured by AgentShield](${shieldsIoBadgeUrl})](${auditVerifyUrl})`;
    const html = `<a href="${auditVerifyUrl}" target="_blank" rel="noopener noreferrer"><img src="${shieldsIoBadgeUrl}" alt="Secured by AgentShield" /></a>`;

    return {
      markdown,
      html,
      shieldsIoBadgeUrl,
    };
  }
}
