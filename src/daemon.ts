import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { AGENTSHIELD_VERSION } from "./version.js";

export interface PeerCredentials {
  uid?: number;
  gid?: number;
  pid?: number;
}

export interface DaemonConfig {
  socketPath?: string;
  authSecret?: string;
  tokenFilePath?: string;
  maxRingBufferEntries?: number;
  /** Restrict IPC connections to these POSIX UIDs (defaults to [process.getuid()] on POSIX) */
  allowedUids?: number[];
  /** Optional custom peer credential resolver (SO_PEERCRED / LOCAL_PEERCRED hook for OS & testing) */
  peerCredentialResolver?: (socket: net.Socket) => PeerCredentials | null;
  /** Enforce strict peer credential verification on every IPC connection (default: true when resolver or POSIX UID policy active) */
  requirePeerCredentials?: boolean;
}

export interface OtelMetricRecord {
  id: string;
  timestamp: number;
  metricName: string;
  value: number;
  unit?: string;
  type: "counter" | "histogram" | "gauge" | "audit_event";
  attributes: Record<string, string | number | boolean>;
}

export interface DaemonLockHandle {
  lockId: string;
  resourceKey: string;
  ownerId: string;
  fenceToken: number;
  acquiredAt: number;
  expiresAt: number;
  leaseTtlMs: number;
}

export interface DaemonStatus {
  version: string;
  uptimeMs: number;
  socketPath: string;
  pid: number;
  activeLocks: number;
  totalOtelEvents: number;
  connectedClients: number;
}

/**
 * Returns the standard OS-specific IPC endpoint:
 * - Windows: Named pipe "\\\\.\\pipe\\agentshield"
 * - Linux / macOS: Unix domain socket "/var/run/agentshield.sock" (or fallback to tmpdir)
 */
export function getDefaultSocketPath(): string {
  if (process.platform === "win32") {
    return "\\\\.\\pipe\\agentshield";
  }

  // Check if /var/run is accessible and writable
  try {
    fs.accessSync("/var/run", fs.constants.W_OK);
    return "/var/run/agentshield.sock";
  } catch {
    return path.join(os.tmpdir(), "agentshield.sock");
  }
}

/**
 * Headless Background Daemon (agentshieldd)
 *
 * Implements a lightweight local daemon communicating over an authenticated
 * Unix domain socket (/var/run/agentshield.sock with permission 0600) or Windows Named Pipe
 * (\\\\.\\pipe\\agentshield) to stream OpenTelemetry metrics and synchronize process locks.
 */
export class AgentShieldDaemon {
  private server: net.Server | null = null;
  private socketPath: string;
  private authSecret: string;
  private tokenFilePath: string;
  private startedAt = 0;
  private globalFenceCounter = 1;
  private activeLocks: Map<string, DaemonLockHandle> = new Map();
  private otelRingBuffer: OtelMetricRecord[] = [];
  private maxRingBufferEntries: number;
  private allowedUids: number[];
  private peerCredentialResolver?: (socket: net.Socket) => PeerCredentials | null;
  private requirePeerCredentials: boolean;
  private activePolicyOverrides: Record<string, unknown> = {};
  private clientSessions: Map<
    net.Socket,
    { authenticated: boolean; id: string; peer?: PeerCredentials | null }
  > = new Map();

  constructor(config: DaemonConfig = {}) {
    this.socketPath = config.socketPath || getDefaultSocketPath();
    this.authSecret = config.authSecret || crypto.randomBytes(32).toString("hex");
    this.maxRingBufferEntries = config.maxRingBufferEntries || 2000;
    const currentUid = typeof process.getuid === "function" ? process.getuid() : undefined;
    this.allowedUids = config.allowedUids ?? (currentUid !== undefined ? [currentUid] : []);
    this.peerCredentialResolver = config.peerCredentialResolver;
    this.requirePeerCredentials =
      config.requirePeerCredentials ?? Boolean(config.peerCredentialResolver);

    const defaultTokenDir = path.join(os.homedir(), ".agentshield");
    this.tokenFilePath = config.tokenFilePath || path.join(defaultTokenDir, "daemon.token");
  }

  public getSocketPath(): string {
    return this.socketPath;
  }

  public getAuthSecret(): string {
    return this.authSecret;
  }

  /**
   * Starts the IPC daemon listening on the domain socket / named pipe.
   */
  public async start(): Promise<void> {
    if (this.server) return;

    // Clean up stale socket file on POSIX systems
    if (process.platform !== "win32" && fs.existsSync(this.socketPath)) {
      try {
        fs.unlinkSync(this.socketPath);
      } catch {
        // ignore if cannot unlink
      }
    }

    // Persist authentication token to secure user-owned directory
    try {
      const tokenDir = path.dirname(this.tokenFilePath);
      if (!fs.existsSync(tokenDir)) {
        fs.mkdirSync(tokenDir, { recursive: true, mode: 0o700 });
      }
      fs.writeFileSync(this.tokenFilePath, this.authSecret, { encoding: "utf8", mode: 0o600 });
    } catch {
      // non-fatal if running in restricted sandboxed test
    }

    this.startedAt = Date.now();

    await new Promise<void>((resolve, reject) => {
      this.server = net.createServer((socket) => this.handleConnection(socket));

      this.server.on("error", (err) => {
        reject(err);
      });

      this.server.listen(this.socketPath, () => {
        // Enforce strict file mode 0600 on Unix domain sockets so only current UID can connect
        if (process.platform !== "win32") {
          try {
            fs.chmodSync(this.socketPath, 0o600);
          } catch {
            // ignore chmod errors in testing environments
          }
        }
        resolve();
      });
    });
  }

  /**
   * Stops the daemon and cleans up IPC endpoints.
   */
  public async stop(): Promise<void> {
    if (!this.server) return;

    for (const [socket] of this.clientSessions) {
      try {
        socket.destroy();
      } catch {
        // ignore
      }
    }
    this.clientSessions.clear();

    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => resolve(), 250);
      this.server?.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
    this.server = null;

    if (process.platform !== "win32" && fs.existsSync(this.socketPath)) {
      try {
        fs.unlinkSync(this.socketPath);
      } catch {
        // ignore
      }
    }
  }

  public getStatus(): DaemonStatus {
    this.purgeExpiredLocks();
    return {
      version: AGENTSHIELD_VERSION,
      uptimeMs: this.startedAt ? Date.now() - this.startedAt : 0,
      socketPath: this.socketPath,
      pid: process.pid,
      activeLocks: this.activeLocks.size,
      totalOtelEvents: this.otelRingBuffer.length,
      connectedClients: this.clientSessions.size,
    };
  }

  public getOtelMetrics(): OtelMetricRecord[] {
    return [...this.otelRingBuffer];
  }

  private verifyPeerCredentials(socket: net.Socket): {
    allowed: boolean;
    peer: PeerCredentials | null;
    reason?: string;
  } {
    if (!this.peerCredentialResolver) {
      return {
        allowed: !this.requirePeerCredentials,
        peer: null,
        reason: this.requirePeerCredentials ? "Missing peer credential resolver" : undefined,
      };
    }
    const peer = this.peerCredentialResolver(socket);
    if (!peer) {
      return {
        allowed: false,
        peer: null,
        reason: "EACCES: Unable to verify IPC peer credentials (SO_PEERCRED)",
      };
    }
    if (
      this.allowedUids.length > 0 &&
      (peer.uid === undefined || !this.allowedUids.includes(peer.uid))
    ) {
      return {
        allowed: false,
        peer,
        reason: `EACCES: Unauthorized IPC peer UID ${peer.uid ?? "unknown"} rejected (allowed: ${this.allowedUids.join(",")})`,
      };
    }
    return { allowed: true, peer };
  }

  private timingSafeTokenMatch(supplied: string): boolean {
    const a = Buffer.from(supplied, "utf8");
    const b = Buffer.from(this.authSecret, "utf8");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  private handleConnection(socket: net.Socket): void {
    const peerCheck = this.verifyPeerCredentials(socket);
    if (!peerCheck.allowed) {
      socket.on("error", () => {});
      this.sendResponse(socket, {
        ok: false,
        code: "EACCES",
        error: peerCheck.reason || "EACCES: Peer credential verification failed",
      });
      socket.end(() => socket.destroy());
      return;
    }

    const sessionId = crypto.randomUUID().slice(0, 8);
    this.clientSessions.set(socket, { authenticated: false, id: sessionId, peer: peerCheck.peer });

    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let newlineIdx = buffer.indexOf("\n");

      while (newlineIdx !== -1) {
        const rawLine = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);

        if (rawLine) {
          this.processCommand(socket, rawLine);
        }

        newlineIdx = buffer.indexOf("\n");
      }
    });

    socket.on("close", () => {
      this.clientSessions.delete(socket);
    });

    socket.on("error", () => {
      this.clientSessions.delete(socket);
    });
  }

  private processCommand(socket: net.Socket, rawLine: string): void {
    const session = this.clientSessions.get(socket);
    if (!session) return;

    try {
      const msg = JSON.parse(rawLine);
      const { action, id } = msg;

      // 1. PING is allowed unauthenticated
      if (action === "PING") {
        this.sendResponse(socket, {
          id,
          ok: true,
          action: "PONG",
          version: AGENTSHIELD_VERSION,
          authenticated: session.authenticated,
        });
        return;
      }

      // 2. AUTH handshake (timing-safe token verification)
      if (action === "AUTH") {
        if (typeof msg.token === "string" && this.timingSafeTokenMatch(msg.token)) {
          session.authenticated = true;
          this.sendResponse(socket, {
            id,
            ok: true,
            message: "Authenticated successfully",
            peerUid: session.peer?.uid,
            peerPid: session.peer?.pid,
          });
        } else {
          this.sendResponse(socket, {
            id,
            ok: false,
            code: "EACCES",
            error: "EACCES: Invalid authentication token",
          });
        }
        return;
      }

      // Guard: all remaining actions require authentication
      if (!session.authenticated) {
        this.sendResponse(socket, {
          id,
          ok: false,
          code: "EACCES",
          error: "Unauthorized: AUTH handshake required before command execution",
        });
        return;
      }

      // 2b. POLICY_SET (requires authenticated, peer-verified session)
      if (action === "POLICY_SET") {
        if (msg.policy && typeof msg.policy === "object") {
          this.activePolicyOverrides = { ...this.activePolicyOverrides, ...msg.policy };
          this.sendResponse(socket, { id, ok: true, policy: this.activePolicyOverrides });
        } else {
          this.sendResponse(socket, { id, ok: false, error: "Missing policy object" });
        }
        return;
      }

      // 3. LOCK_ACQUIRE
      if (action === "LOCK_ACQUIRE") {
        const { resourceKey, ownerId, leaseTtlMs } = msg;
        const result = this.acquireLock(resourceKey, ownerId, leaseTtlMs);
        this.sendResponse(socket, { id, ...result });
        return;
      }

      // 4. LOCK_RELEASE
      if (action === "LOCK_RELEASE") {
        const { resourceKey, lockId, ownerId } = msg;
        const released = this.releaseLock(resourceKey, lockId, ownerId);
        this.sendResponse(socket, { id, ok: released });
        return;
      }

      // 5. LOCK_STATUS
      if (action === "LOCK_STATUS") {
        const { resourceKey } = msg;
        this.purgeExpiredLocks();
        const lock = this.activeLocks.get(resourceKey);
        this.sendResponse(socket, {
          id,
          ok: true,
          locked: Boolean(lock),
          lock: lock || null,
        });
        return;
      }

      // 6. STREAM_OTEL
      if (action === "STREAM_OTEL") {
        const { metricName, value, unit, type, attributes } = msg;
        const record: OtelMetricRecord = {
          id: `otel_${crypto.randomUUID().slice(0, 8)}`,
          timestamp: Date.now(),
          metricName: String(metricName || "agentshield.execution"),
          value: Number(value ?? 1),
          unit: unit || "1",
          type: type || "counter",
          attributes: attributes || {},
        };

        this.recordOtelMetric(record);
        this.sendResponse(socket, { id, ok: true, metricId: record.id });
        return;
      }

      // 7. GET_METRICS / STATUS
      if (action === "GET_METRICS") {
        this.sendResponse(socket, {
          id,
          ok: true,
          status: this.getStatus(),
          metrics: this.otelRingBuffer.slice(-50),
        });
        return;
      }

      this.sendResponse(socket, { id, ok: false, error: `Unknown daemon action: ${action}` });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      this.sendResponse(socket, { ok: false, error: `Malformed IPC message: ${errMsg}` });
    }
  }

  private sendResponse(socket: net.Socket, data: Record<string, unknown>): void {
    if (socket.writable) {
      socket.write(`${JSON.stringify(data)}\n`);
    }
  }

  private purgeExpiredLocks(): void {
    const now = Date.now();
    for (const [key, lock] of this.activeLocks.entries()) {
      if (lock.expiresAt <= now) {
        this.activeLocks.delete(key);
      }
    }
  }

  private acquireLock(
    resourceKey: string,
    ownerId?: string,
    leaseTtlMs = 5000,
  ): { ok: boolean; lock?: DaemonLockHandle; error?: string } {
    if (!resourceKey) {
      return { ok: false, error: "Missing resourceKey" };
    }

    this.purgeExpiredLocks();
    const existing = this.activeLocks.get(resourceKey);

    if (existing) {
      return {
        ok: false,
        error: `Resource '${resourceKey}' is locked by owner '${existing.ownerId}' until ${new Date(existing.expiresAt).toISOString()}`,
      };
    }

    const fenceToken = ++this.globalFenceCounter;
    const now = Date.now();
    const handle: DaemonLockHandle = {
      lockId: `lock_${crypto.randomUUID().slice(0, 10)}`,
      resourceKey,
      ownerId: ownerId || `worker_${crypto.randomUUID().slice(0, 6)}`,
      fenceToken,
      acquiredAt: now,
      expiresAt: now + leaseTtlMs,
      leaseTtlMs,
    };

    this.activeLocks.set(resourceKey, handle);
    return { ok: true, lock: handle };
  }

  private releaseLock(resourceKey: string, lockId: string, ownerId?: string): boolean {
    if (!resourceKey) return false;
    this.purgeExpiredLocks();

    const current = this.activeLocks.get(resourceKey);
    if (!current) return true; // Already expired or released

    // Guard against releasing an hijacked lock
    if (current.lockId === lockId) {
      if (ownerId && current.ownerId !== ownerId) {
        return false;
      }
      this.activeLocks.delete(resourceKey);
      return true;
    }

    return false;
  }

  private recordOtelMetric(record: OtelMetricRecord): void {
    this.otelRingBuffer.push(record);
    if (this.otelRingBuffer.length > this.maxRingBufferEntries) {
      this.otelRingBuffer.shift();
    }
  }
}

/**
 * High-speed IPC Client for AgentShield, DBShield, and IDE Extensions
 * to communicate with the headless agentshieldd daemon.
 */
export class AgentShieldDaemonClient {
  private socket: net.Socket | null = null;
  private socketPath: string;
  private pendingRequests: Map<
    string,
    { resolve: (val: Record<string, unknown>) => void; reject: (err: unknown) => void }
  > = new Map();
  private incomingBuffer = "";

  constructor(socketPath?: string) {
    this.socketPath = socketPath || getDefaultSocketPath();
  }

  public async connect(timeoutMs = 3000): Promise<void> {
    if (this.socket) return;

    return new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let connected = false;

      const timer = setTimeout(() => {
        if (!connected) {
          socket.destroy();
          reject(new Error(`Timed out connecting to agentshieldd socket: ${this.socketPath}`));
        }
      }, timeoutMs);

      socket.on("connect", () => {
        connected = true;
        clearTimeout(timer);
        this.socket = socket;
        this.initSocketListeners(socket);
        resolve();
      });

      socket.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  public disconnect(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.pendingRequests.clear();
  }

  public async ping(): Promise<Record<string, unknown>> {
    return this.sendRequest({ action: "PING" });
  }

  public async authenticate(token: string): Promise<boolean> {
    const res = await this.sendRequest({ action: "AUTH", token });
    return Boolean(res.ok);
  }

  public async acquireLock(
    resourceKey: string,
    options: { ownerId?: string; leaseTtlMs?: number } = {},
  ): Promise<DaemonLockHandle | null> {
    const res = await this.sendRequest({
      action: "LOCK_ACQUIRE",
      resourceKey,
      ownerId: options.ownerId,
      leaseTtlMs: options.leaseTtlMs,
    });
    return res.ok ? (res.lock as DaemonLockHandle) : null;
  }

  public async releaseLock(
    resourceKey: string,
    lockId: string,
    ownerId?: string,
  ): Promise<boolean> {
    const res = await this.sendRequest({
      action: "LOCK_RELEASE",
      resourceKey,
      lockId,
      ownerId,
    });
    return Boolean(res.ok);
  }

  public async streamOtelMetric(
    metricName: string,
    value: number,
    attributes: Record<string, string | number | boolean> = {},
    type: "counter" | "histogram" | "gauge" | "audit_event" = "counter",
  ): Promise<string | null> {
    const res = await this.sendRequest({
      action: "STREAM_OTEL",
      metricName,
      value,
      attributes,
      type,
    });
    return res.ok ? (res.metricId as string) : null;
  }

  public async getMetricsSummary(): Promise<Record<string, unknown>> {
    return this.sendRequest({ action: "GET_METRICS" });
  }

  private sendRequest(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (!this.socket || !this.socket.writable) {
      return Promise.reject(new Error("AgentShieldDaemonClient is not connected"));
    }

    const requestId = crypto.randomUUID().slice(0, 8);
    const msg = { ...payload, id: requestId };

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(requestId, { resolve, reject });
      this.socket?.write(`${JSON.stringify(msg)}\n`);
    });
  }

  private initSocketListeners(socket: net.Socket): void {
    socket.on("data", (chunk) => {
      this.incomingBuffer += chunk.toString("utf8");
      let newlineIdx = this.incomingBuffer.indexOf("\n");

      while (newlineIdx !== -1) {
        const line = this.incomingBuffer.slice(0, newlineIdx).trim();
        this.incomingBuffer = this.incomingBuffer.slice(newlineIdx + 1);

        if (line) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.id && this.pendingRequests.has(parsed.id)) {
              const req = this.pendingRequests.get(parsed.id);
              if (req) {
                this.pendingRequests.delete(parsed.id);
                req.resolve(parsed);
              }
            }
          } catch {
            // ignore malformed response frames
          }
        }
        newlineIdx = this.incomingBuffer.indexOf("\n");
      }
    });

    socket.on("close", () => {
      this.disconnect();
    });
  }
}
