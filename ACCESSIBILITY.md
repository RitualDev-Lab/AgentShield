# Accessibility Statement for AgentShield

AgentShield is committed to ensuring digital accessibility for all developers, security auditors, and contributors, including individuals with disabilities.

---

## 💻 CLI & Terminal Accessibility

The AgentShield CLI is designed with the following accessibility standards in mind:

1. **High Contrast Terminal Output:**
   - Color outputs are accompanied by clear text-based prefixes (`[ALERT]`, `[CLEAN]`, `[PASSED]`, `[FAILED]`, `[CRITICAL]`) so users with color-vision deficiencies (protanopia, deuteranopia, tritanopia) are never reliant on color alone to discern threat severity.

2. **Screen Reader Compatibility:**
   - Clean, linearized output formatted for terminal screen readers (Orca, NVDA, JAWS, VoiceOver).
   - Structured JSON mode (`--json`) is supported across all CLI commands (`scan`, `ci`, `compliance`) to allow programmatic parsing and speech rendering.

3. **Plain Text Fallback:**
   - Piped stream mode (`npx @ritualdev-lab/agentshield stream`) strips unnecessary terminal formatting codes, providing clean standard UNIX stream processing.

---

## 🌐 Web & Documentation Accessibility

Our documentation and web portal conform to **WCAG 2.1 Level AA** standards:
- Semantic HTML tags (`<main>`, `<header>`, `<nav>`, `<article>`).
- Minimum color contrast ratio of **4.5:1** for standard text and **3:1** for large text and UI controls.
- Full keyboard navigability (Tab, Shift+Tab, Enter, Escape).
- Responsive design adaptable to zoom levels up to **200%** without loss of functionality.

---

## 📢 Feedback & Reporting Barriers

If you experience accessibility barriers while using AgentShield CLI or documentation, please submit an issue on our [GitHub Issues](https://github.com/RitualDev-Lab/AgentShield/issues) with the tag `accessibility` or email **accessibility@ritualdev.lab**.
