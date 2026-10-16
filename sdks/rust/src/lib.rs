//! Official Rust client for AgentShield:
//! Zero-leak secret defense, surrogate token rehydration, and shell command sandboxing.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

#[derive(Serialize)]
struct JsonRpcRequest<'a, T: Serialize> {
    jsonrpc: &'a str,
    id: i64,
    method: &'a str,
    params: T,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: i64,
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Finding {
    #[serde(rename = "patternId")]
    pub pattern_id: String,
    #[serde(rename = "patternName")]
    pub pattern_name: String,
    pub category: String,
    pub severity: String,
    pub raw: String,
    pub redacted: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ScanResult {
    #[serde(rename = "hasSecrets")]
    pub has_secrets: bool,
    pub findings: Vec<Finding>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RedactResult {
    #[serde(rename = "hasSecrets")]
    pub has_secrets: bool,
    #[serde(rename = "sanitizedText")]
    pub sanitized_text: String,
    pub findings: Vec<Finding>,
    #[serde(rename = "redactedCount")]
    pub redacted_count: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CommandInspection {
    #[serde(rename = "isBlocked")]
    pub is_blocked: bool,
    pub reason: Option<String>,
    pub category: Option<String>,
}

#[derive(Deserialize)]
struct RehydrateResponse {
    #[serde(rename = "rehydratedText")]
    rehydrated_text: String,
}

pub struct AgentShieldClient {
    child: Mutex<Child>,
    reader: Mutex<BufReader<std::process::ChildStdout>>,
    req_id: AtomicI64,
}

impl AgentShieldClient {
    /// Launches the AgentShield sidecar daemon via stdio JSON-RPC.
    pub fn new() -> Result<Self, String> {
        let mut child = Command::new("npx")
            .args(["@ritualdev-lab/agentshield", "sidecar"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to spawn AgentShield sidecar: {e}"))?;

        let stdout = child.stdout.take().ok_or("Failed to capture child stdout")?;
        let reader = BufReader::new(stdout);

        Ok(Self {
            child: Mutex::new(child),
            reader: Mutex::new(reader),
            req_id: AtomicI64::new(1),
        })
    }

    fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, String> {
        let id = self.req_id.fetch_add(1, Ordering::SeqCst);
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        let req_json = serde_json::to_string(&req).map_err(|e| e.to_string())?;

        {
            let mut child = self.child.lock().map_err(|e| e.to_string())?;
            let stdin = child.stdin.as_mut().ok_or("Child stdin closed")?;
            writeln!(stdin, "{req_json}").map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())?;
        }

        let mut line = String::new();
        {
            let mut reader = self.reader.lock().map_err(|e| e.to_string())?;
            reader.read_line(&mut line).map_err(|e| e.to_string())?;
        }

        let resp: JsonRpcResponse<R> =
            serde_json::from_str(&line).map_err(|e| format!("Invalid JSON-RPC response: {e}"))?;

        if let Some(err) = resp.error {
            return Err(format!("AgentShield error ({}): {}", err.code, err.message));
        }

        resp.result.ok_or_else(|| "Missing result payload in response".to_string())
    }

    /// Scans text for secret tokens.
    pub fn scan(&self, text: &str) -> Result<ScanResult, String> {
        #[derive(Serialize)]
        struct Params<'a> {
            text: &'a str,
        }
        self.call("shield.scan", Params { text })
    }

    /// Scans and redacts detected secrets, returning sanitized text with surrogate tokens.
    pub fn scan_and_redact(&self, text: &str) -> Result<RedactResult, String> {
        #[derive(Serialize)]
        struct Params<'a> {
            text: &'a str,
            #[serde(rename = "maskStyle")]
            mask_style: &'a str,
        }
        self.call(
            "shield.scanAndRedact",
            Params {
                text,
                mask_style: "token",
            },
        )
    }

    /// Restores surrogate tokens back to their original values in memory.
    pub fn rehydrate(&self, text: &str) -> Result<String, String> {
        #[derive(Serialize)]
        struct Params<'a> {
            text: &'a str,
        }
        let res: RehydrateResponse = self.call("shield.rehydrate", Params { text })?;
        Ok(res.rehydrated_text)
    }

    /// Inspects a command string before OS execution.
    pub fn inspect_command(&self, command: &str) -> Result<CommandInspection, String> {
        #[derive(Serialize)]
        struct Params<'a> {
            command: &'a str,
        }
        self.call("shield.inspectCommand", Params { command })
    }
}

impl Drop for AgentShieldClient {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}
