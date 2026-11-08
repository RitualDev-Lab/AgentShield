import assert from "node:assert/strict";
import test from "node:test";
import {
  EbpfSocketFilter,
  MacOSEndpointSecurityManager,
  WindowsWFPController,
  getKernelSecurityStack,
  getOsIsolationGuarantee,
} from "../src/index.js";

test("Phase 3: Low-Level OS Kernel Primitives Suite", async (t) => {
  await t.test(
    "Linux eBPF Socket Monitoring via libbpf (sys_enter_connect) blocks metadata and unauthorized egress",
    () => {
      const socketFilter = new EbpfSocketFilter();
      const testPid = 42001;

      socketFilter.attachProcess(testPid, {
        allowDns: true,
        allowLoopback: true,
        allowedPorts: [80, 443, 53, 22],
        blockedPorts: [2375, 6379, 5432],
        blockedCidrs: ["10.99.0.0/16"],
      });

      // 1. Link-local IMDS metadata connection is blocked immediately
      const metadataRes = socketFilter.evaluateConnect(testPid, "169.254.169.254", 80);
      assert.equal(metadataRes.allowed, false);
      assert.equal(metadataRes.actionTaken, "BLOCK_EPERM");
      assert.ok(metadataRes.reason?.includes("EPERM"));

      // 2. DNS query on port 53 is allowed
      const dnsRes = socketFilter.evaluateConnect(testPid, "1.1.1.1", 53);
      assert.equal(dnsRes.allowed, true);
      assert.equal(dnsRes.actionTaken, "ALLOW");

      // 3. Approved HTTPS connection to public IP is allowed
      const httpsRes = socketFilter.evaluateConnect(testPid, "140.82.121.4", 443);
      assert.equal(httpsRes.allowed, true);
      assert.equal(httpsRes.actionTaken, "ALLOW");

      // 4. Blocked port (Docker socket port 2375) is blocked
      const dockerPortRes = socketFilter.evaluateConnect(testPid, "127.0.0.1", 2375);
      assert.equal(dockerPortRes.allowed, false);
      assert.equal(dockerPortRes.actionTaken, "BLOCK_EPERM");

      // 5. Unapproved port (8080) is blocked
      const unapprovedPortRes = socketFilter.evaluateConnect(testPid, "104.26.10.1", 8080);
      assert.equal(unapprovedPortRes.allowed, false);
      assert.equal(unapprovedPortRes.actionTaken, "BLOCK_EPERM");

      // 6. Blocked internal CIDR is denied
      const cidrRes = socketFilter.evaluateConnect(testPid, "10.99.4.5", 443);
      assert.equal(cidrRes.allowed, false);
      assert.equal(cidrRes.actionTaken, "BLOCK_EPERM");

      socketFilter.detachProcess(testPid);
    },
  );

  await t.test(
    "macOS Endpoint Security Framework (ESF) system extension enforces AUTH hooks and replaces sandbox-exec",
    async () => {
      const esManager = new MacOSEndpointSecurityManager({
        enforceCodeSigning: true,
      });

      const status = await esManager.subscribe();
      assert.equal(status.active, true);
      assert.equal(status.clientSubscribed, true);
      assert.ok(status.esfVersion.includes("macOS ESF"));

      const testPid = 55100;
      const testPpid = 55000;

      // 1. ES_EVENT_TYPE_AUTH_EXEC: Block unauthorized binaries
      const execBlocked = esManager.authorizeExec({
        pid: testPid,
        ppid: testPpid,
        processPath: "/usr/bin/nc",
      });
      assert.equal(execBlocked.result, "ES_AUTH_RESULT_DENY");
      assert.ok(execBlocked.reason?.includes("Endpoint Security policy"));

      // 2. ES_EVENT_TYPE_AUTH_EXEC: Allow signed benign compilers/tools
      const execAllowed = esManager.authorizeExec({
        pid: testPid,
        ppid: testPpid,
        processPath: "/usr/bin/git",
        signingId: "com.apple.git",
        teamId: "APPLE_TEAM_ID",
      });
      assert.equal(execAllowed.result, "ES_AUTH_RESULT_ALLOW");

      // 3. ES_EVENT_TYPE_AUTH_OPEN: Block opening sensitive credential boundaries
      const openAwsBlocked = esManager.authorizeOpen({
        pid: testPid,
        ppid: testPpid,
        processPath: "/usr/local/bin/node",
        targetPath: "/Users/developer/.aws/credentials",
      });
      assert.equal(openAwsBlocked.result, "ES_AUTH_RESULT_DENY");
      assert.ok(openAwsBlocked.reason?.includes("sensitive credential boundary"));

      // 4. ES_EVENT_TYPE_AUTH_OPEN: Allow standard workspace project file
      const openWorkspaceAllowed = esManager.authorizeOpen({
        pid: testPid,
        ppid: testPpid,
        processPath: "/usr/local/bin/node",
        targetPath: "/Users/developer/project/src/index.ts",
      });
      assert.equal(openWorkspaceAllowed.result, "ES_AUTH_RESULT_ALLOW");

      // 5. ES_EVENT_TYPE_AUTH_CONNECT: Block link-local metadata
      const connectBlocked = esManager.authorizeConnect({
        pid: testPid,
        ppid: testPpid,
        processPath: "/usr/local/bin/node",
        targetIp: "169.254.169.254",
        targetPort: 80,
      });
      assert.equal(connectBlocked.result, "ES_AUTH_RESULT_DENY");

      esManager.unsubscribe();
    },
  );

  await t.test(
    "Windows LowBox AppContainer + WFP callout driver enforces per-PID packet filtering without admin rights",
    async () => {
      const appContainerSid = "S-1-15-2-123456789-987654321";
      const wfp = new WindowsWFPController(appContainerSid);

      const status = await wfp.initialize();
      assert.equal(status.active, true);
      assert.ok(status.engineHandle.startsWith("0x"));
      assert.equal(status.appContainerSid, appContainerSid);

      const workerPid = 7712;
      wfp.addRule({
        targetPid: workerPid,
        appContainerSid,
        allowLocalhost: false,
        allowedPorts: [443, 80],
        blockedPorts: [2375, 445],
        blockedRemoteSubnets: ["192.168.1."],
      });

      // 1. Link-local metadata blocked
      const metaRes = wfp.evaluateConnect({
        pid: workerPid,
        remoteIp: "169.254.169.254",
        remotePort: 80,
        appContainerSid,
      });
      assert.equal(metaRes.allowed, false);
      assert.equal(metaRes.actionTaken, "FWP_ACTION_BLOCK");

      // 2. Localhost breakout blocked by policy
      const localRes = wfp.evaluateConnect({
        pid: workerPid,
        remoteIp: "127.0.0.1",
        remotePort: 8080,
        appContainerSid,
      });
      assert.equal(localRes.allowed, false);
      assert.equal(localRes.actionTaken, "FWP_ACTION_BLOCK");
      assert.ok(localRes.reason?.includes("Localhost IPC breakout"));

      // 3. Blocked SMB port 445 blocked
      const smbRes = wfp.evaluateConnect({
        pid: workerPid,
        remoteIp: "10.0.0.5",
        remotePort: 445,
        appContainerSid,
      });
      assert.equal(smbRes.allowed, false);
      assert.equal(smbRes.actionTaken, "FWP_ACTION_BLOCK");

      // 4. Approved outbound HTTPS allowed
      const okRes = wfp.evaluateConnect({
        pid: workerPid,
        remoteIp: "20.112.52.29",
        remotePort: 443,
        appContainerSid,
      });
      assert.equal(okRes.allowed, true);
      assert.equal(okRes.actionTaken, "FWP_ACTION_PERMIT");

      wfp.shutdown();
    },
  );

  await t.test("getKernelSecurityStack returns verified low-level primitives per OS", () => {
    const linuxStack = getKernelSecurityStack("linux");
    assert.equal(linuxStack.filesystemIsolation, "landlock");
    assert.equal(linuxStack.networkEgressIsolation, "ebpf_sys_enter_connect");
    assert.equal(linuxStack.isZeroEgressSupported, true);

    const macStack = getKernelSecurityStack("darwin");
    assert.equal(macStack.filesystemIsolation, "esf_auth_open");
    assert.equal(macStack.networkEgressIsolation, "esf_auth_connect");
    assert.equal(macStack.processExecutionIsolation, "esf_auth_exec");
    assert.equal(macStack.isZeroEgressSupported, true);

    const winStack = getKernelSecurityStack("win32");
    assert.equal(winStack.filesystemIsolation, "appcontainer_sid");
    assert.equal(winStack.networkEgressIsolation, "wfp_ale_connect");
    assert.equal(winStack.isZeroEgressSupported, true);
  });
});
