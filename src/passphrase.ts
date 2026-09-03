import { execSync, spawnSync } from "node:child_process";

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
/**
 * Windows only: encrypt the passphrase with DPAPI (bound to the current
 * Windows session) and write the blob to filePath. The plaintext travels
 * to PowerShell via stdin — never argv, never env.
 */
export function protectPassphraseDpapi(passphrase: string, filePath: string): void {
  if (process.platform !== "win32") {
    throw new Error(
      "DPAPI is Windows-only. On macOS use the keychain (`security add-generic-password`), on Linux `secret-tool store` — see docs/integrations/claude-code.md."
    );
  }
  const script =
    "$plain = [Console]::In.ReadToEnd().TrimEnd([char]13, [char]10); " +
    "if ($plain.Length -eq 0) { exit 2 }; " +
    "$ss = ConvertTo-SecureString $plain -AsPlainText -Force; " +
    `$ss | ConvertFrom-SecureString | Out-File -Encoding ascii '${filePath.replace(/'/g, "''")}'`;
  const result = spawnSync("powershell", ["-NoProfile", "-Command", script], {
    input: passphrase,
    windowsHide: true,
    timeout: 30_000,
  });
  if (result.status !== 0) {
    throw new Error(
      `DPAPI protection failed (exit ${result.status}): ${result.stderr?.toString().slice(0, 300)}`
    );
  }
}

/** The command that decrypts what protectPassphraseDpapi wrote. */
export function dpapiDecryptCommand(filePath: string): string {
  return `powershell -NoProfile -Command "[Net.NetworkCredential]::new('', (Get-Content '${filePath}' | ConvertTo-SecureString)).Password"`;
}

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
