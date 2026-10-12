const { execSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repoDir = process.cwd();
const wikiSourceDir = path.join(repoDir, "wiki");
const tempWikiDir = path.join(repoDir, ".wiki-tmp");

console.log("🛡️ [AgentShield Wiki Sync] Preparing wiki documentation for deployment...");

if (!fs.existsSync(wikiSourceDir)) {
  console.error("❌ Error: wiki/ directory does not exist.");
  process.exit(1);
}

try {
  if (fs.existsSync(tempWikiDir)) {
    fs.rmSync(tempWikiDir, { recursive: true, force: true });
  }

  console.log("🔗 Connecting to GitHub Wiki remote...");
  try {
    execSync("git clone https://github.com/RitualDev-Lab/AgentShield.wiki.git .wiki-tmp", {
      cwd: repoDir,
      stdio: "pipe",
    });
    console.log("✅ Cloned existing wiki repository.");
  } catch (err) {
    console.log("⚠️ Wiki repository not yet created on GitHub.");
    console.log('💡 To activate: Visit https://github.com/RitualDev-Lab/AgentShield/wiki and click "Create the first page".');
    console.log("📦 All wiki pages are safely tracked in the /wiki directory in the main repo.");
    process.exit(0);
  }

  const files = fs.readdirSync(wikiSourceDir);
  for (const file of files) {
    const src = path.join(wikiSourceDir, file);
    const dest = path.join(tempWikiDir, file);
    fs.copyFileSync(src, dest);
    console.log(`  + Synced: ${file}`);
  }

  execSync("git add .", { cwd: tempWikiDir });
  try {
    execSync('git commit -m "docs(wiki): update AgentShield technical architecture wiki"', {
      cwd: tempWikiDir,
    });
    execSync("git push origin master", { cwd: tempWikiDir });
    console.log("🎉 Successfully published all wiki pages to GitHub Wiki!");
  } catch (commitErr) {
    console.log("ℹ️ No changes to commit in wiki repository.");
  }
} catch (error) {
  console.error("❌ Wiki sync error:", error.message);
} finally {
  if (fs.existsSync(tempWikiDir)) {
    try {
      fs.rmSync(tempWikiDir, { recursive: true, force: true });
    } catch (_) {}
  }
}
