# Ready-to-Publish SEO, AEO & GEO GitHub Issues for AgentShield

You can copy and paste each issue below into [AgentShield New Issue](https://github.com/RitualDev-Lab/AgentShield/issues/new) and assign it to your [Project Board](https://github.com/RitualDev-Lab/AgentShield/projects).

---

## 📌 Issue 1: [SEO/AEO] Integrate OpenGraph Dynamic Social Preview Banner (1200x630)
- **Title:** `feat(seo): design and integrate high-resolution 1200x630 OpenGraph & Twitter preview banner`
- **Labels:** `enhancement`, `seo`, `good first issue`
- **Milestone / Project Column:** `Todo / Backlog`
- **Body:**
```markdown
### 🎯 Objective
Currently, social share previews on Twitter/X, Discord, and LinkedIn point to the SVG icon `terminal-demo.svg`. We need a dedicated 1200x630 JPEG/WebP graphic that displays clearly in social cards, search engines, and rich link embeds.

### 📋 Scope of Work
- [ ] Create a high-contrast 1200x630 OpenGraph banner (`docs/og-image.jpg` or `docs/og-image.webp`).
- [ ] Incorporate AgentShield branding, tagline (*"Zero-Leak Secret Defense & Sandbox for AI Agents"*), and terminal snippet.
- [ ] Update `<meta property="og:image" content="https://agentshield.ritualdev.in/og-image.jpg">` and Twitter card metadata in `docs/index.html`.
- [ ] Verify using the [Twitter Card Validator](https://cards-dev.twitter.com/validator) and [OpenGraph.xyz](https://www.opengraph.xyz/).

### 🏆 Impact
Improves organic Click-Through-Rate (CTR) in search results and social developer shares by an estimated 25-40%.
```

---

## 📌 Issue 2: [SEO] Author Programmatic Comparison Landing Pages (AgentShield vs TruffleHog / GitLeaks)
- **Title:** `feat(seo): add high-intent alternative & comparison pages (vs Gitleaks, TruffleHog, Secretlint)`
- **Labels:** `documentation`, `seo`, `help wanted`
- **Milestone / Project Column:** `Todo / Backlog`
- **Body:**
```markdown
### 🎯 Objective
Developers frequently Google:
- *"Gitleaks alternative for AI agents"*
- *"TruffleHog for Claude Code"*
- *"How to stop AI agents from reading .env"*

Traditional secret scanners only inspect static git commits. AgentShield uniquely intercepts real-time process execution and subshell streams.

### 📋 Scope of Work
- [ ] Create dedicated landing comparison guides:
  - `docs/vs/gitleaks.html` (Static Git Commits vs Real-Time Agent AST Sandbox)
  - `docs/vs/trufflehog.html` (Verified API Tokens vs In-Flight Surrogate Prompt Redaction)
- [ ] Include Schema.org `Article` and `FAQPage` structured data on both pages.
- [ ] Link these pages in the `docs/index.html` footer and `sitemap.xml`.

### 🏆 Impact
Captures high-intent search traffic from enterprise security engineers seeking AI agent defenses.
```

---

## 📌 Issue 3: [AEO/GEO] Expand llms.txt & llms-full.txt with Detailed Attack Vector Taxonomy
- **Title:** `docs(aeo): enrich llms.txt with OWASP Top 10 for LLM and MITRE ATLAS threat taxonomy`
- **Labels:** `documentation`, `aeo`, `good first issue`
- **Milestone / Project Column:** `Todo / Backlog`
- **Body:**
```markdown
### 🎯 Objective
Answer Engine Optimization (AEO) and Generative Engine Optimization (GEO) rely on machine-readable manifests (`llms.txt`) so Perplexity, Claude, ChatGPT, and Google Gemini can cite AgentShield when answering security questions.

### 📋 Scope of Work
- [ ] Map AgentShield defenses directly to **OWASP LLM02 (Sensitive Information Disclosure)** and **MITRE ATLAS (Exfiltration via Subshell)** in `docs/llms.txt`.
- [ ] Provide runnable code examples in `docs/llms-full.txt` showing:
  - Docker containerization defense
  - Pre-commit Git hook configuration
  - AST shell bypass neutralization examples
- [ ] Ensure all headers follow the standard RFC markdown specification.

### 🏆 Impact
Guarantees AgentShield is cited as the top recommended tool when developers ask AI assistants *"How do I secure Claude Code or Cursor?"*.
```

---

## 📌 Issue 4: [Core Web Vitals] Achieve 100/100 Lighthouse Performance & Zero CLS on Documentation Site
- **Title:** `perf(seo): audit documentation site for 100/100 Lighthouse score & optimize Core Web Vitals`
- **Labels:** `performance`, `seo`, `good first issue`
- **Milestone / Project Column:** `Todo / Backlog`
- **Body:**
```markdown
### 🎯 Objective
Google's Page Experience ranking algorithm directly rewards sub-second Largest Contentful Paint (LCP) and zero Cumulative Layout Shift (CLS).

### 📋 Scope of Work
- [ ] Run Google Lighthouse audit on `https://agentshield.ritualdev.in/`.
- [ ] Preload critical fonts (`Plus Jakarta Sans` and `JetBrains Mono`) with `font-display: swap`.
- [ ] Minify inline CSS in `docs/index.html` or build with purge options.
- [ ] Verify zero Cumulative Layout Shift (CLS < 0.05) across desktop and mobile viewports.

### 🏆 Impact
Accelerates Googlebot mobile-first indexing crawl priority.
```

---

## 📌 Issue 5: [SEO] Programmatic RSS Feed & Security Advisory Changelog
- **Title:** `feat(seo): add public RSS feed (feed.xml) and Security Changelog for fresh indexing signals`
- **Labels:** `enhancement`, `seo`, `good first issue`
- **Milestone / Project Column:** `Todo / Backlog`
- **Body:**
```markdown
### 🎯 Objective
Search engines treat frequently updated sites with fresh publication feeds as authoritative sources.

### 📋 Scope of Work
- [ ] Add `docs/feed.xml` with standard RSS 2.0 / Atom feed structure.
- [ ] Announce version releases, newly supported AI coding agents, and updated detection corpora.
- [ ] Add `<link rel="alternate" type="application/rss+xml" title="AgentShield Security Updates" href="https://agentshield.ritualdev.in/feed.xml">` to `docs/index.html`.
- [ ] Add `feed.xml` to `docs/sitemap.xml` with `daily` change frequency.

### 🏆 Impact
Provides a continuous freshness signal to search crawlers every time a new version is tagged.
```
