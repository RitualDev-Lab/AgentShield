"""
AgentShield Python Sidecar Client:
Connects to the AgentShield Node.js / Agnostic JSON-RPC 2.0 Sidecar Daemon
for sub-millisecond scanning, streaming redaction, and compliance evaluation.
Falls back automatically to the in-process StandaloneEngine if Node is unavailable.
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional
from .standalone import StandaloneEngine, AgentCommandSandbox


class AgentShieldClient:
    """
    Client for AgentShield JSON-RPC 2.0 sidecar daemon with automatic fallback
    to the in-process pure-Python engine.
    """

    def __init__(
        self,
        sidecar_binary: Optional[str] = None,
        use_fallback: bool = True,
    ) -> None:
        self.sidecar_binary = sidecar_binary
        self.use_fallback = use_fallback
        self._proc: Optional[subprocess.Popen[str]] = None
        self._request_id = 0
        self._fallback_engine = StandaloneEngine() if use_fallback else None
        self._fallback_sandbox = AgentCommandSandbox() if use_fallback else None

        self._start_sidecar()

    def _find_binary(self) -> Optional[List[str]]:
        if self.sidecar_binary:
            return [self.sidecar_binary, "sidecar"]

        # Check for local npx / node executable
        if shutil.which("agentshield"):
            return ["agentshield", "sidecar"]
        if shutil.which("npx"):
            return ["npx", "@ritualdev-lab/agentshield", "sidecar"]

        return None

    def _start_sidecar(self) -> None:
        cmd = self._find_binary()
        if not cmd:
            return

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except Exception:
            self._proc = None

    def is_sidecar_active(self) -> bool:
        """Returns True if the external Node.js daemon is connected."""
        return self._proc is not None and self._proc.poll() is None

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self.is_sidecar_active():
            if not self.use_fallback:
                raise RuntimeError(
                    "AgentShield sidecar daemon is not running and use_fallback=False."
                )
            return self._call_fallback(method, params or {})

        self._request_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or {},
        }

        try:
            assert self._proc and self._proc.stdin and self._proc.stdout
            self._proc.stdin.write(json.dumps(req) + "\n")
            self._proc.stdin.flush()
            line = self._proc.stdout.readline()
            if not line:
                raise RuntimeError("Sidecar daemon terminated unexpectedly.")
            res = json.loads(line)
            if "error" in res:
                raise RuntimeError(f"AgentShield error ({res['error'].get('code')}): {res['error'].get('message')}")
            return res.get("result")
        except Exception:
            if self.use_fallback:
                return self._call_fallback(method, params or {})
            raise

    def _call_fallback(self, method: str, params: Dict[str, Any]) -> Any:
        assert self._fallback_engine and self._fallback_sandbox
        if method in ("shield.scan", "scan"):
            findings = self._fallback_engine.scan(params.get("text", ""))
            return {"hasSecrets": len(findings) > 0, "findings": findings}
        elif method in ("shield.scanAndRedact", "scan_and_redact", "redact"):
            return self._fallback_engine.scan_and_redact(
                params.get("text", ""),
                mask_style=params.get("maskStyle", "token"),
            )
        elif method in ("shield.rehydrate", "rehydrate"):
            return {
                "rehydratedText": self._fallback_engine.rehydrate(params.get("text", ""))
            }
        elif method in ("shield.inspectCommand", "inspect_command", "sandbox"):
            return self._fallback_sandbox.inspect_command(params.get("command", ""))
        elif method in ("shield.ping", "ping"):
            return "pong"
        elif method in ("shield.health", "health"):
            return {"status": "ok", "mode": "in-process-fallback"}
        raise NotImplementedError(f"Method '{method}' not supported in fallback mode.")

    def scan(self, text: str) -> Dict[str, Any]:
        """Scans text for secrets."""
        return self._call("shield.scan", {"text": text})

    def scan_and_redact(
        self, text: str, mask_style: str = "token"
    ) -> Dict[str, Any]:
        """Scans and redacts credentials in text, returning sanitized string."""
        return self._call("shield.scanAndRedact", {"text": text, "maskStyle": mask_style})

    def rehydrate(self, text: str) -> str:
        """Restores surrogate tokens back to original secrets."""
        res = self._call("shield.rehydrate", {"text": text})
        return res.get("rehydratedText", text)

    def inspect_command(self, command: str) -> Dict[str, Any]:
        """Inspects shell commands before execution."""
        return self._call("shield.inspectCommand", {"command": command})

    def close(self) -> None:
        """Closes the sidecar daemon process."""
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=1)
            except Exception:
                pass
            self._proc = None

    def __enter__(self) -> "AgentShieldClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
