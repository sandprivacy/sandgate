// Portable test invocation: enumerate compiled test files and pass them
// explicitly. `node --test` glob args need Node >= 21, directory args are
// flaky on Windows, and bare discovery picks up src/*.ts on Node builds
// with default type stripping. Explicit paths work everywhere.
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";

const files = readdirSync("dist/test")
  .filter((f) => f.endsWith(".test.js"))
  .map((f) => `dist/test/${f}`);

if (files.length === 0) {
  console.error("No compiled tests found — run `npm run build` first.");
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...files], {
  stdio: "inherit",
});
process.exit(result.status ?? 1);
