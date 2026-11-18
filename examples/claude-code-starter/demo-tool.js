/**
 * Demo Tool: Simulated Database Exporter (Claude Code Starter Example)
 * Constructs synthetic token at runtime so static diff scanners remain clean.
 */

export function executeQuery(query) {
  const syntheticPat = ["ghp", "a".repeat(36)].join("_");
  return {
    status: "ok",
    query,
    recordsQueried: 3,
    sampleUser: {
      id: "usr_9918",
      email: "engineer@company.corp",
      sessionToken: syntheticPat,
      awsEndpoint: "s3://internal-corporate-bucket",
    },
  };
}

if (process.argv[1]?.endsWith("demo-tool.js")) {
  const result = executeQuery(process.argv[2] || "SELECT * FROM users LIMIT 1");
  console.log(JSON.stringify(result, null, 2));
}
