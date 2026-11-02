/**
 * Process-Level Network Egress Filtering & CIDR Boundary Engine
 *
 * Enforces OS-level and application-level network egress controls for AI coding agents:
 * - Denies access to cloud instance metadata endpoints (169.254.169.254 / fd00:ec2::254 / metadata.google.internal)
 * - Denies localhost and loopback bypass evasions (127.0.0.0/8, 0.0.0.0, hex/octal/decimal IP encodings)
 * - Restricts private network ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 * - Blocks unapproved external C2 tunnels and exfiltration endpoints (ngrok, webhook.site, interactsh, etc.)
 */

export interface NetworkEgressPolicy {
  denyMetadata?: boolean; // default: true
  denyLoopback?: boolean; // default: true
  denyPrivateNetworks?: boolean; // default: false
  allowedDomains?: string[]; // e.g. ["api.github.com", "*.npmjs.org"]
  blockedDomains?: string[]; // e.g. ["*.ngrok.io", "*.webhook.site"]
  allowedCidrs?: string[]; // e.g. ["192.168.1.0/24"]
  blockedCidrs?: string[]; // explicit custom CIDR denials
  airGapped?: boolean; // 100% offline private VPC: zero outbound public traffic, allows local LLMs (Ollama, vLLM)
  allowLocalLlm?: boolean; // default: true in air-gapped mode
}

export const LOCAL_LLM_PORTS = [11434, 8000, 1234];
export const LOCAL_LLM_HOSTS = ["localhost", "127.0.0.1", "::1", "ollama", "vllm.local"];

export function isLocalLlmTarget(target: string): boolean {
  const normalized = target.toLowerCase().trim();
  const host = extractHostFromTarget(normalized);
  const isLocalHost = LOCAL_LLM_HOSTS.includes(host) || host.endsWith(".local");

  if (!isLocalHost) return false;

  // Check if port is specified or matches local LLM defaults (Ollama: 11434, vLLM: 8000, LM Studio: 1234)
  for (const port of LOCAL_LLM_PORTS) {
    if (normalized.includes(`:${port}`)) return true;
  }

  return normalized.includes("ollama") || normalized.includes("vllm");
}

export interface NetworkEgressVerdict {
  isBlocked: boolean;
  reason?: string;
  category?: "metadata_imds" | "loopback_bypass" | "c2_exfiltration" | "policy_denied";
  target?: string;
  normalizedHost?: string;
}

/** Known cloud metadata endpoints */
const CLOUD_METADATA_IPS = [
  "169.254.169.254", // AWS, GCP, Azure, DigitalOcean IMDS
  "100.100.100.200", // Alibaba Cloud IMDS
  "::ffff:169.254.169.254",
  "fd00:ec2::254", // AWS IPv6 IMDS
];

const CLOUD_METADATA_HOSTS = ["metadata.google.internal", "metadata.goog", "instance-data"];

/** Standard unapproved C2 / reverse proxy / exfiltration domains */
const KNOWN_C2_DOMAINS = [
  "*.ngrok.io",
  "*.ngrok-free.app",
  "*.ngrok.app",
  "*.requestcatcher.com",
  "*.oastify.com",
  "*.burpcollaborator.net",
  "*.interactsh.com",
  "*.pipedream.net",
  "*.webhook.site",
  "*.beeceptor.com",
  "*.run.app",
  "*.serveo.net",
  "*.localtunnel.me",
  "*.trycloudflare.com",
];

/**
 * Normalizes and converts various IPv4 representations (dotted-decimal, hex, octal, integer)
 * into a standard 32-bit unsigned integer. Returns null if invalid.
 */
export function ipToUint32(input: string): number | null {
  const trimmed = input.trim().replace(/^\[|\]$/g, "");

  // Handle IPv6-mapped IPv4 (e.g. ::ffff:127.0.0.1)
  const mappedMatch = trimmed.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mappedMatch) {
    return ipToUint32(mappedMatch[1]);
  }

  // Handle 32-bit single integer representation (e.g. 2130706433 for 127.0.0.1)
  if (/^\d{8,10}$/.test(trimmed)) {
    const val = Number.parseInt(trimmed, 10);
    if (val >= 0 && val <= 0xffffffff) {
      return val >>> 0;
    }
  }

  // Handle single hexadecimal integer (e.g. 0x7f000001)
  if (/^0x[0-9a-fA-F]{1,8}$/i.test(trimmed)) {
    const val = Number.parseInt(trimmed, 16);
    if (val >= 0 && val <= 0xffffffff) {
      return val >>> 0;
    }
  }

  // Standard or mixed octet format (e.g. 127.0.0.1, 0177.0.0.1, 0x7f.0.0.1)
  const parts = trimmed.split(".");
  if (parts.length !== 4) return null;

  let acc = 0;
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    let octet: number;

    if (/^0x[0-9a-fA-F]+$/i.test(part)) {
      octet = Number.parseInt(part, 16);
    } else if (/^0[0-7]+$/.test(part)) {
      octet = Number.parseInt(part, 8);
    } else if (/^\d+$/.test(part)) {
      octet = Number.parseInt(part, 10);
    } else {
      return null;
    }

    if (octet < 0 || octet > 255) return null;
    acc = ((acc << 8) | octet) >>> 0;
  }

  return acc >>> 0;
}

/**
 * Checks whether an IPv4 address falls within a given CIDR block.
 */
export function isIpInCidr(ipStr: string, cidr: string): boolean {
  const [range, prefixStr] = cidr.split("/");
  if (!range || !prefixStr) return false;

  const prefix = Number.parseInt(prefixStr, 10);
  if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipInt = ipToUint32(ipStr);
  const rangeInt = ipToUint32(range);
  if (ipInt === null || rangeInt === null) return false;

  if (prefix === 0) return true;

  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

/**
 * Matches a hostname against a domain pattern (supports wildcard prefixes like `*.domain.com`).
 */
export function matchesDomain(host: string, pattern: string): boolean {
  const normHost = host.toLowerCase().trim();
  const normPattern = pattern.toLowerCase().trim();

  if (normPattern.startsWith("*.")) {
    const suffix = normPattern.slice(1); // e.g. ".ngrok.io"
    return normHost.endsWith(suffix) || normHost === normPattern.slice(2);
  }

  return normHost === normPattern;
}

/**
 * Extracts host from target URL or host string.
 */
export function extractHostFromTarget(target: string): string {
  let cleaned = target.trim();
  // Strip common CLI command flags/quotes
  cleaned = cleaned.replace(/^['"]|['"]$/g, "");

  // If protocol-relative or full URL
  try {
    if (cleaned.startsWith("//")) {
      cleaned = `http:${cleaned}`;
    } else if (!/^https?:\/\//i.test(cleaned)) {
      cleaned = `http://${cleaned}`;
    }
    const parsed = new URL(cleaned);
    return parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  } catch {
    // Fallback: split on colon/slash
    const noProto = target.replace(/^[a-zA-Z]+:\/\//, "");
    const hostPart = noProto.split(/[/:?#]/)[0] || target;
    return hostPart.toLowerCase().replace(/^\[|\]$/g, "");
  }
}

/**
 * Evaluates a network target (URL or hostname/IP) against security egress policies.
 */
export function evaluateNetworkEgress(
  target: string,
  policy: NetworkEgressPolicy = {},
): NetworkEgressVerdict {
  const isAirGapped = Boolean(
    policy.airGapped ||
      process.env.AGENTSHIELD_AIR_GAPPED === "1" ||
      process.env.AGENTSHIELD_AIR_GAPPED === "true" ||
      process.env.RITUAL_AIR_GAPPED === "1" ||
      process.env.RITUAL_AIR_GAPPED === "true",
  );
  const allowLocalLlm =
    policy.allowLocalLlm === true || (isAirGapped && policy.allowLocalLlm !== false);
  const isLocalLlm = allowLocalLlm && isLocalLlmTarget(target);

  const denyMetadata = policy.denyMetadata !== false;
  const denyLoopback = isLocalLlm ? false : policy.denyLoopback !== false;
  const denyPrivate = Boolean(policy.denyPrivateNetworks);

  const host = extractHostFromTarget(target);
  const ipInt = ipToUint32(host);
  const isIp = ipInt !== null;

  // 1. Cloud Metadata IMDS Check (Always blocked, even in air-gapped/local mode)
  if (denyMetadata) {
    if (
      CLOUD_METADATA_IPS.includes(host) ||
      CLOUD_METADATA_HOSTS.some((h) => matchesDomain(host, h))
    ) {
      return {
        isBlocked: true,
        reason: `Egress blocked: target '${host}' is a protected cloud instance metadata endpoint (IMDS).`,
        category: "metadata_imds",
        target,
        normalizedHost: host,
      };
    }

    if (isIp) {
      if (isIpInCidr(host, "169.254.0.0/16") || isIpInCidr(host, "100.100.100.200/32")) {
        return {
          isBlocked: true,
          reason: `Egress blocked: IP '${host}' targets protected cloud instance metadata (169.254.169.254 IMDS).`,
          category: "metadata_imds",
          target,
          normalizedHost: host,
        };
      }
    }
  }

  // 1.5 Air-Gapped Mode Handling
  if (isAirGapped) {
    if (isLocalLlm) {
      return {
        isBlocked: false,
        target,
        normalizedHost: host,
      };
    }

    // Check if target matches explicitly allowed private VPC domains or CIDRs
    const isExplicitlyAllowed =
      policy.allowedDomains?.some((d) => matchesDomain(host, d)) ||
      (policy.allowedCidrs && isIp && policy.allowedCidrs.some((cidr) => isIpInCidr(host, cidr)));

    if (!isExplicitlyAllowed) {
      return {
        isBlocked: true,
        reason:
          "Egress blocked: Air-Gapped / Private VPC mode active. Zero outbound internet traffic allowed. Only authorized local LLM runtimes (Ollama, vLLM, LM Studio) or internal VPC endpoints are permitted.",
        category: "policy_denied",
        target,
        normalizedHost: host,
      };
    }
  }

  // 2. Localhost & Loopback Bypass Check
  if (denyLoopback) {
    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host === "localtest.me" ||
      host.endsWith(".localtest.me") ||
      host === "lvh.me" ||
      host.endsWith(".lvh.me") ||
      host === "vcap.me" ||
      host.endsWith(".vcap.me") ||
      host === "::1" ||
      host === "0.0.0.0"
    ) {
      return {
        isBlocked: true,
        reason: `Egress blocked: target '${host}' is a local loopback hostname or IPv6 loopback address.`,
        category: "loopback_bypass",
        target,
        normalizedHost: host,
      };
    }

    if (isIp) {
      if (isIpInCidr(host, "127.0.0.0/8") || isIpInCidr(host, "0.0.0.0/8")) {
        return {
          isBlocked: true,
          reason: `Egress blocked: IP '${host}' resolves to localhost loopback boundary (127.0.0.0/8 or 0.0.0.0).`,
          category: "loopback_bypass",
          target,
          normalizedHost: host,
        };
      }
    }
  }

  // 3. Private Network CIDRs (RFC 1918)
  if (denyPrivate && isIp) {
    const privateCidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
    for (const cidr of privateCidrs) {
      if (isIpInCidr(host, cidr)) {
        return {
          isBlocked: true,
          reason: `Egress blocked: target IP '${host}' belongs to restricted private network (${cidr}).`,
          category: "policy_denied",
          target,
          normalizedHost: host,
        };
      }
    }
  }

  // 4. Custom Blocked CIDRs
  if (policy.blockedCidrs && isIp) {
    for (const cidr of policy.blockedCidrs) {
      if (isIpInCidr(host, cidr)) {
        return {
          isBlocked: true,
          reason: `Egress blocked: target IP '${host}' is matched by blocked CIDR '${cidr}'.`,
          category: "policy_denied",
          target,
          normalizedHost: host,
        };
      }
    }
  }

  // 5. Blocked Domains / Known C2 Domains
  const blockedDomainList = [...(policy.blockedDomains || []), ...KNOWN_C2_DOMAINS];
  for (const pattern of blockedDomainList) {
    if (matchesDomain(host, pattern)) {
      return {
        isBlocked: true,
        reason: `Egress blocked: target '${host}' matches unapproved C2 or exfiltration domain '${pattern}'.`,
        category: "c2_exfiltration",
        target,
        normalizedHost: host,
      };
    }
  }

  // 6. Whitelist Enforcement (if specified)
  if (policy.allowedDomains && policy.allowedDomains.length > 0) {
    const isAllowed = policy.allowedDomains.some((d) => matchesDomain(host, d));
    if (!isAllowed) {
      return {
        isBlocked: true,
        reason: `Egress blocked: target '${host}' is not in approved outbound domain allowlist.`,
        category: "policy_denied",
        target,
        normalizedHost: host,
      };
    }
  }

  return {
    isBlocked: false,
    normalizedHost: host,
  };
}

/**
 * Scans a shell command line for outbound network client calls and validates destination targets.
 */
export function inspectCommandForEgress(
  command: string,
  policy: NetworkEgressPolicy = {},
): NetworkEgressVerdict {
  // Common networking tools
  const networkBinaries =
    /\b(curl|wget|invoke-webrequest|irm|iwr|nc|ncat|netcat|socat|telnet|ssh|ping)\b/i;
  if (!networkBinaries.test(command)) {
    return { isBlocked: false };
  }

  // Extract URLs and IP/host patterns from arguments
  const urlMatches = command.match(/https?:\/\/[^\s'"<>)]+/gi) || [];
  for (const url of urlMatches) {
    const verdict = evaluateNetworkEgress(url, policy);
    if (verdict.isBlocked) {
      return verdict;
    }
  }

  // Extract bare host:port or IP arguments (e.g. curl 169.254.169.254 or nc 127.0.0.1 8080)
  const bareMatches = command.match(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g) || [];
  for (const rawIp of bareMatches) {
    const verdict = evaluateNetworkEgress(rawIp, policy);
    if (verdict.isBlocked) {
      return verdict;
    }
  }

  // Extract alternative numeric/hex representations: 0x7f000001, 2130706433
  const altIpMatches = command.match(/\b(?:0x[0-9a-fA-F]{8}|\d{10})\b/g) || [];
  for (const altIp of altIpMatches) {
    const verdict = evaluateNetworkEgress(altIp, policy);
    if (verdict.isBlocked) {
      return verdict;
    }
  }

  return { isBlocked: false };
}
