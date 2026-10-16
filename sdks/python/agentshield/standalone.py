"""
Pure-Python AgentShield Engine:
Provides in-process, zero-dependency secret detection, Shannon entropy verification,
in-memory surrogate token rehydration, and command sandboxing for Python AI agents.
"""

from __future__ import annotations
import math
import re
from typing import Any, Dict, List, Optional, Pattern


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy (base 2) of a given string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class StandaloneEngine:
    """
    In-process secret defense engine for Python AI applications
    (LangChain, LlamaIndex, CrewAI, AutoGen, and LangGraph).
    """

    PATTERNS: List[Dict[str, Any]] = [
        {
            "id": "openai-api-key",
            "name": "OpenAI API Key",
            "category": "ai",
            "severity": "critical",
            "regex": re.compile(r"\bsk-proj-[a-zA-Z0-9_\-]{20,}\b"),
        },
        {
            "id": "anthropic-api-key",
            "name": "Anthropic Claude API Key",
            "category": "ai",
            "severity": "critical",
            "regex": re.compile(r"\bsk-ant-[a-zA-Z0-9_\-]{20,}\b"),
        },
        {
            "id": "stripe-live-key",
            "name": "Stripe Live Secret Key",
            "category": "saas",
            "severity": "critical",
            "regex": re.compile(r"\bsk_live_[a-zA-Z0-9]{20,}\b"),
        },
        {
            "id": "aws-access-key-id",
            "name": "AWS Access Key ID",
            "category": "cloud",
            "severity": "high",
            "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        },
        {
            "id": "github-pat",
            "name": "GitHub Personal Access Token",
            "category": "vcs",
            "severity": "high",
            "regex": re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b"),
        },
        {
            "id": "slack-webhook",
            "name": "Slack Incoming Webhook",
            "category": "saas",
            "severity": "high",
            "regex": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        },
        {
            "id": "private-key-block",
            "name": "Private Key Block",
            "category": "crypto",
            "severity": "critical",
            "regex": re.compile(
                r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?(?:PRIVATE )?KEY(?: BLOCK)?-----[\s\S]+?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?(?:PRIVATE )?KEY(?: BLOCK)?-----"
            ),
        },
    ]

    def __init__(self) -> None:
        self._vault: Dict[str, str] = {}

    def scan(self, text: str) -> List[Dict[str, Any]]:
        """Scans input text and returns a list of detected secret findings."""
        findings: List[Dict[str, Any]] = []
        if not text:
            return findings

        for p in self.PATTERNS:
            regex: Pattern[str] = p["regex"]
            for match in regex.finditer(text):
                raw = match.group(0)
                findings.append(
                    {
                        "patternId": p["id"],
                        "patternName": p["name"],
                        "category": p["category"],
                        "severity": p["severity"],
                        "raw": raw,
                        "start": match.start(),
                        "end": match.end(),
                    }
                )
        return findings

    def scan_and_redact(
        self, text: str, mask_style: str = "token"
    ) -> Dict[str, Any]:
        """
        Scans and redacts detected secrets, storing originals in the in-memory vault.
        Returns a dict containing 'hasSecrets', 'sanitizedText', 'findings', and 'redactedCount'.
        """
        findings = self.scan(text)
        if not findings:
            return {
                "hasSecrets": False,
                "sanitizedText": text,
                "findings": [],
                "redactedCount": 0,
            }

        # Sort findings descending by start to safely slice and replace
        sorted_findings = sorted(findings, key=lambda f: f["start"], reverse=True)
        sanitized = list(text)

        redacted_records = []
        for f in sorted_findings:
            raw = f["raw"]
            if mask_style == "asterisk":
                replacement = "*" * len(raw)
            elif mask_style == "hash":
                # Deterministic short hash token
                h = hex(abs(hash(raw)))[2:10]
                replacement = f"[AGENT_SHIELD:HASH:{h}]"
            else:
                # Surrogate token format: [AGENT_SHIELD:<CATEGORY>:<FINGERPRINT>]
                h = hex(abs(hash(raw)))[2:10]
                category_upper = f["category"].upper()
                replacement = f"[AGENT_SHIELD:{category_upper}:{h}]"
                self._vault[replacement] = raw

            sanitized[f["start"] : f["end"]] = list(replacement)
            redacted_records.append({**f, "redacted": replacement})

        result_text = "".join(sanitized)
        return {
            "hasSecrets": True,
            "sanitizedText": result_text,
            "findings": redacted_records,
            "redactedCount": len(redacted_records),
        }

    def rehydrate(self, text: str) -> str:
        """Restores surrogate tokens back to their original values from the vault."""
        rehydrated = text
        for token, original in self._vault.items():
            rehydrated = rehydrated.replace(token, original)
        return rehydrated


class AgentCommandSandbox:
    """Pre-flight command inspection firewall for Python agent executions."""

    FORBIDDEN_COMMANDS = [
        (re.compile(r"\b(cat|more|less|tail|head|type|gc|Get-Content)\s+[^\s|;&><]*\.env", re.I), "Blocked attempt to read raw .env file"),
        (re.compile(r"\b(printenv|export)\b(?:\s*$|\s*[|;&])", re.I), "Blocked attempt to dump entire process environment"),
        (re.compile(r"curl\s+.*[?&](?:token|key|secret|password|api_key)=", re.I), "Blocked credential exfiltration via HTTP query parameters"),
        (re.compile(r"/(?:etc/shadow|\.ssh/id_rsa|\.aws/credentials)", re.I), "Blocked attempt to access protected system credentials"),
    ]

    def inspect_command(self, command: str) -> Dict[str, Any]:
        """Inspects shell command string against security firewall rules."""
        if not command:
            return {"isBlocked": False, "command": ""}

        trimmed = command.strip()
        for pattern, reason in self.FORBIDDEN_COMMANDS:
            if pattern.search(trimmed):
                return {
                    "isBlocked": True,
                    "reason": reason,
                    "command": trimmed,
                }

        return {
            "isBlocked": False,
            "command": trimmed,
        }
