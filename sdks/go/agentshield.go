// Package agentshield provides Go bindings and sidecar client integration for AgentShield:
// Zero-leak secret defense, in-memory surrogate rehydration, and shell command sandboxing.
package agentshield

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
)

// JsonRpcRequest represents a JSON-RPC 2.0 request payload.
type JsonRpcRequest struct {
	JsonRpc string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JsonRpcResponse represents a standard JSON-RPC 2.0 response.
type JsonRpcResponse struct {
	JsonRpc string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JsonRpcError   `json:"error,omitempty"`
}

// JsonRpcError represents a JSON-RPC error object.
type JsonRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ScanResult holds the outcome of a secret scan.
type ScanResult struct {
	HasSecrets bool      `json:"hasSecrets"`
	Findings   []Finding `json:"findings"`
}

// Finding represents an individual intercepted secret token.
type Finding struct {
	PatternID   string `json:"patternId"`
	PatternName string `json:"patternName"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Raw         string `json:"raw"`
	Redacted    string `json:"redacted"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
}

// RedactResult holds the sanitized string and secret metadata.
type RedactResult struct {
	HasSecrets    bool      `json:"hasSecrets"`
	SanitizedText string    `json:"sanitizedText"`
	Findings      []Finding `json:"findings"`
	RedactedCount int       `json:"redactedCount"`
}

// CommandInspection holds the sandbox evaluation for a shell command.
type CommandInspection struct {
	IsBlocked        bool   `json:"isBlocked"`
	Reason           string `json:"reason,omitempty"`
	SanitizedCommand string `json:"sanitizedCommand,omitempty"`
	Category         string `json:"category,omitempty"`
}

// Client manages communication with the AgentShield sidecar daemon.
type Client struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	reader  *bufio.Reader
	mu      sync.Mutex
	reqID   int64
	closing bool
}

// NewClient initializes a connection to the AgentShield sidecar daemon via stdio.
func NewClient(ctx context.Context, customBinary ...string) (*Client, error) {
	binary := "npx"
	args := []string{"@ritualdev-lab/agentshield", "sidecar"}

	if len(customBinary) > 0 && customBinary[0] != "" {
		binary = customBinary[0]
		args = []string{"sidecar"}
	} else if path, err := exec.LookPath("agentshield"); err == nil {
		binary = path
		args = []string{"sidecar"}
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("agentshield: failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("agentshield: failed to create stdout pipe: %w", err)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("agentshield: failed to start sidecar (%s): %w", binary, err)
	}

	return &Client{
		cmd:    cmd,
		stdin:  stdin,
		reader: bufio.NewReader(stdout),
	}, nil
}

func (c *Client) call(ctx context.Context, method string, params interface{}, result interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closing {
		return errors.New("agentshield: client is closed")
	}

	id := atomic.AddInt64(&c.reqID, 1)
	req := JsonRpcRequest{
		JsonRpc: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("agentshield: marshal request failed: %w", err)
	}

	if _, err := fmt.Fprintf(c.stdin, "%s\n", string(reqBytes)); err != nil {
		return fmt.Errorf("agentshield: write to sidecar failed: %w", err)
	}

	line, err := c.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("agentshield: read response failed: %w", err)
	}

	var resp JsonRpcResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return fmt.Errorf("agentshield: unmarshal response failed: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("agentshield error (%d): %s", resp.Error.Code, resp.Error.Message)
	}

	if result != nil {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("agentshield: unmarshal result payload failed: %w", err)
		}
	}

	return nil
}

// Scan inspects text for exposed credentials.
func (c *Client) Scan(ctx context.Context, text string) (*ScanResult, error) {
	var res ScanResult
	err := c.call(ctx, "shield.scan", map[string]interface{}{"text": text}, &res)
	return &res, err
}

// ScanAndRedact scrubs secrets from text, returning sanitized text with surrogate tokens.
func (c *Client) ScanAndRedact(ctx context.Context, text string, maskStyle ...string) (*RedactResult, error) {
	style := "token"
	if len(maskStyle) > 0 && maskStyle[0] != "" {
		style = maskStyle[0]
	}
	var res RedactResult
	err := c.call(ctx, "shield.scanAndRedact", map[string]interface{}{"text": text, "maskStyle": style}, &res)
	return &res, err
}

// Rehydrate restores surrogate tokens back to their original values in memory.
func (c *Client) Rehydrate(ctx context.Context, text string) (string, error) {
	var res struct {
		RehydratedText string `json:"rehydratedText"`
	}
	err := c.call(ctx, "shield.rehydrate", map[string]interface{}{"text": text}, &res)
	return res.RehydratedText, err
}

// InspectCommand checks a command string against the AgentShield sandbox policy firewall.
func (c *Client) InspectCommand(ctx context.Context, command string) (*CommandInspection, error) {
	var res CommandInspection
	err := c.call(ctx, "shield.inspectCommand", map[string]interface{}{"command": command}, &res)
	return &res, err
}

// Close gracefully closes the sidecar client process.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closing = true
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		return c.cmd.Wait()
	}
	return nil
}
