import { execSync } from "node:child_process";

/**
 * Resolve the vault passphrase for non-interactive runs (MCP clients
 * launching `sandgate serve`). Two sources, in order:
 *
 *  - SANDGATE_PASSPHRASE: the value itself. Simple, but sits in cleartext
 *    in whatever config launches the server.
 *  - SANDGATE_PASSPHRASE_CMD: a command whose stdout is the passphrase —
 *    the git-credential/restic pattern. Point it at the OS secret store:
 *    DPAPI on Windows, `security find-generic-password` on macOS,
 *    `secret-tool lookup` on Linux, or any password manager CLI.
 *
 * Either way the model never sees it: it lives in the launcher's
 * environment, not in the agent's context.
 */
export function resolvePassphrase(env: NodeJS.ProcessEnv): string | undefined {
  if (env.SANDGATE_PASSPHRASE) return env.SANDGATE_PASSPHRASE;
  const command = env.SANDGATE_PASSPHRASE_CMD;
  if (!command) return undefined;
  const output = execSync(command, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 15_000,
  });
  const pass = output.trim();
  return pass.length > 0 ? pass : undefined;
}
