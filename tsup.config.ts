import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

const pkg = JSON.parse(readFileSync("./package.json", "utf-8"));

export default defineConfig({
  entry: ["src/index.ts", "src/cli.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  minify: false,
  shims: true,
  define: {
    __AGENTSHIELD_VERSION__: JSON.stringify(pkg.version),
  },
});
