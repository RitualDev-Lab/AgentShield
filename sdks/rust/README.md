# 🦀 AgentShield Rust SDK (`agentshield-defense`)

[![Crates.io](https://img.shields.io/crates/v/agentshield-defense.svg)](https://crates.io/crates/agentshield-defense)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Rust client for **[AgentShield](https://github.com/RitualDev-Lab/AgentShield)**: Zero-leak secret defense, in-memory surrogate token rehydration, and shell command sandboxing.

---

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
agentshield-defense = "0.2.2"
```

Requires `agentshield` CLI or `npx` on PATH.

---

## 🚀 Usage

```rust
use agentshield_defense::AgentShieldClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AgentShieldClient::new()?;

    // 1. Scan and redact in-flight secrets
    let prompt = "Deploy using key sk-proj-placeholder-token";
    let redact_result = client.scan_and_redact(prompt)?;

    println!("Sanitized: {}", redact_result.sanitized_text);
    // Sanitized: Deploy using key [AGENT_SHIELD:AI:...]

    // 2. Rehydrate locally
    let original = client.rehydrate(&redact_result.sanitized_text)?;
    println!("Rehydrated: {}", original);

    // 3. Inspect shell commands before agent execution
    let check = client.inspect_command("cat .env")?;
    if check.is_blocked {
        println!("🚨 Blocked: {:?}", check.reason);
    }

    Ok(())
}
```

---

## 🛡️ License

MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
