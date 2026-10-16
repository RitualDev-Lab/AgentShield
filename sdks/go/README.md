# 🦫 AgentShield Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/RitualDev-Lab/agentshield/sdks/go.svg)](https://pkg.go.dev/github.com/RitualDev-Lab/agentshield/sdks/go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Go SDK for **[AgentShield](https://github.com/RitualDev-Lab/AgentShield)**: Zero-leak secret defense, in-memory surrogate token rehydration, and command sandboxing for Go AI applications and agent proxies.

---

## 📦 Installation

```bash
go get github.com/RitualDev-Lab/agentshield/sdks/go
```

Requires `agentshield` CLI or `node` on system PATH.

---

## 🚀 Usage

### 1. Connecting to the Sidecar

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/RitualDev-Lab/agentshield/sdks/go"
)

func main() {
	ctx := context.Background()
	client, err := agentshield.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to start AgentShield client: %v", err)
	}
	defer client.Close()

	// Redact secrets in-flight
	prompt := "Query user data using OpenAI key sk-proj-placeholder-token"
	res, err := client.ScanAndRedact(ctx, prompt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Sanitized:", res.SanitizedText)
	// Sanitized: Query user data using OpenAI key [AGENT_SHIELD:AI:...]

	// Rehydrate tokens back locally
	original, _ := client.Rehydrate(ctx, res.SanitizedText)
	fmt.Println("Rehydrated:", original)
}
```

### 2. Sandbox Command Inspection

```go
check, err := client.InspectCommand(ctx, "cat .env")
if err != nil {
    log.Fatal(err)
}
if check.IsBlocked {
    fmt.Printf("🚨 Blocked: %s\n", check.Reason)
}
```

### 3. HTTP Server Middleware

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/chat", handleChat)

// Wrap with AgentShield to automatically scrub all incoming request bodies
loggedMux := agentshield.HTTPMiddleware(client)(mux)
http.ListenAndServe(":8080", loggedMux)
```

---

## 🛡️ License

MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
