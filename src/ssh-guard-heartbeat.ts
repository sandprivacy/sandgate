import { existsSync, readFileSync, writeFileSync, rmSync, statfsSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import os from "node:os";
import { deriveKey, seal, aadForStatus } from "./pwacrypto.js";
import { VERSION } from "./version.js";
import type { SshGuardConfig } from "./ssh-guard.js";
import type { Finding } from "./ssh-guard-install.js";

/**
 * The heartbeat: every few minutes the server tells your phone it is
 * alive and how it is wired — sealed with the pairing key, so the relay
 * forwards a blob it cannot read. The relay only learns *when* it last
 * heard from the pairing, which is what lets it warn your phone when a
 * server goes quiet.
 *
 * It runs from a systemd timer, apart from the login path: a heartbeat
 * that fails changes nothing about who can log in.
 */

export const HEARTBEAT_INTERVAL_SEC = 300;
export const SERVICE_FILE = "/etc/systemd/system/sandgate-heartbeat.service";
export const TIMER_FILE = "/etc/systemd/system/sandgate-heartbeat.timer";

export interface ServerStatus {
  v: 1;
  ts: number;
  intervalSec: number;
  sandgate: string;
  name?: string;
  host: string;
  os?: string;
  openssh?: string;
  ips: string[];
  mode: "notify" | "enforce";
  keyOnly: boolean;
  hatch: boolean;
  /** doctor's verdict: problems and warnings only, "ok" lines left out. */
  doctor: { ok: boolean; findings: Array<{ level: "warn" | "fail"; label: string; detail?: string }> } | null;
  uptimeSec: number;
  load: number[];
  cpus: number;
  mem: { total: number; free: number };
  disk?: { total: number; free: number };
}

/** PRETTY_NAME from /etc/os-release, e.g. "Ubuntu 20.04.6 LTS". */
export function parseOsRelease(text: string): string | undefined {
  const m = text.match(/^PRETTY_NAME=(?:"([^"]*)"|(.*))$/m);
  return (m?.[1] ?? m?.[2])?.trim() || undefined;
}

/** "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11, OpenSSL …" → "8.2p1". */
export function parseOpensshVersion(text: string): string | undefined {
  return text.match(/OpenSSH_([0-9][\w.]*)/)?.[1];
}

const PRIVATE_V4 = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;
const PRIVATE_V6 = /^(::1$|f[cd]|fe[89ab])/i;

/**
 * The addresses people would ssh to: public ones first. A server behind
 * NAT has none, and then its private ones are still better than nothing.
 */
export function serverAddresses(ifaces: NodeJS.Dict<os.NetworkInterfaceInfo[]>): string[] {
  const all: os.NetworkInterfaceInfo[] = [];
  for (const [name, list] of Object.entries(ifaces)) {
    // Container and VPN bridges are noise on the phone.
    if (/^(docker|br-|veth|virbr|lo)/.test(name)) continue;
    for (const info of list ?? []) if (!info.internal) all.push(info);
  }
  const isPrivate = (i: os.NetworkInterfaceInfo) =>
    i.family === "IPv4" ? PRIVATE_V4.test(i.address) : PRIVATE_V6.test(i.address);
  const pub = all.filter((i) => !isPrivate(i));
  const pick = (pub.length ? pub : all).filter((i) => !(i.family === "IPv6" && PRIVATE_V6.test(i.address)));
  const v4 = pick.filter((i) => i.family === "IPv4").map((i) => i.address);
  const v6 = pick.filter((i) => i.family === "IPv6").map((i) => i.address);
  return [...new Set([...v4, ...v6])].slice(0, 4);
}

function opensshVersion(): string | undefined {
  // `sshd -V` exists only on recent releases; older ones reject the flag
  // but still print their version on the way out. Either way: stderr.
  for (const [cmd, args] of [["sshd", ["-V"]], ["/usr/sbin/sshd", ["-V"]], ["ssh", ["-V"]]] as const) {
    const r = spawnSync(cmd, [...args], { encoding: "utf8", timeout: 5000 });
    const v = parseOpensshVersion(`${r.stderr ?? ""}${r.stdout ?? ""}`);
    if (v) return v;
  }
  return undefined;
}

export function collectStatus(
  config: SshGuardConfig,
  findings: Finding[] | null,
  keyOnly: boolean
): ServerStatus {
  let osName: string | undefined;
  try {
    osName = parseOsRelease(readFileSync("/etc/os-release", "utf8"));
  } catch {
    osName = `${os.type()} ${os.release()}`;
  }
  let disk: ServerStatus["disk"];
  try {
    const s = statfsSync("/");
    disk = { total: s.blocks * s.bsize, free: s.bavail * s.bsize };
  } catch {
    disk = undefined;
  }
  const flagged = (findings ?? [])
    .filter((f): f is Finding & { level: "warn" | "fail" } => f.level !== "ok")
    .map((f) => ({ level: f.level, label: f.label, detail: f.detail?.slice(0, 400) }));
  return {
    v: 1,
    ts: Date.now(),
    intervalSec: HEARTBEAT_INTERVAL_SEC,
    sandgate: VERSION,
    name: config.serverName,
    host: os.hostname(),
    os: osName,
    openssh: opensshVersion(),
    ips: serverAddresses(os.networkInterfaces()),
    mode: config.failOpen === true ? "notify" : "enforce",
    keyOnly,
    hatch: (config.exemptUsers ?? []).length > 0 || config.failOpen === true,
    doctor: findings ? { ok: !flagged.some((f) => f.level === "fail"), findings: flagged } : null,
    uptimeSec: Math.round(os.uptime()),
    load: os.loadavg().map((n) => Math.round(n * 100) / 100),
    cpus: os.cpus().length,
    mem: { total: os.totalmem(), free: os.freemem() },
    disk,
  };
}

/**
 * Seal and post one heartbeat. Throws with the reason on failure.
 * "skipped": the relay had one from us seconds ago (a timer firing twice
 * around an install) — nothing is wrong, and nothing to log as a failure.
 */
export async function sendHeartbeat(config: SshGuardConfig, status: ServerStatus): Promise<"sent" | "skipped"> {
  const payload = seal(deriveKey(config.secret), status, aadForStatus(config.pairId));
  const res = await fetch(new URL("/api/status", config.relayUrl), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pairId: config.pairId, payload, intervalSec: status.intervalSec }),
    signal: AbortSignal.timeout(20_000),
  });
  if (res.status === 429) return "skipped";
  if (!res.ok) throw new Error(`relay answered HTTP ${res.status}`);
  return "sent";
}

/**
 * Tell the relay this server is going away on purpose (uninstall), so a
 * heartbeat that stops is not reported as a server that died.
 */
export async function sendGoodbye(config: SshGuardConfig): Promise<void> {
  await fetch(new URL("/api/status", config.relayUrl), {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pairId: config.pairId }),
    signal: AbortSignal.timeout(10_000),
  });
}

const quote = (arg: string) => (/[\s"\\]/.test(arg) ? `"${arg.replace(/(["\\])/g, "\\$1")}"` : arg);

/** The two unit files. `argv` is the sandgate invocation up to the subcommand. */
export function heartbeatUnits(argv: string[], configPath: string, defaultConfigPath: string) {
  const env = configPath !== defaultConfigPath ? `Environment=SANDGATE_SSH_GUARD_CONFIG=${quote(configPath)}\n` : "";
  const service =
    "# sandgate ssh-guard (managed)\n" +
    "[Unit]\n" +
    "Description=sandgate heartbeat: tell your phone this server is alive\n" +
    "After=network-online.target\n" +
    "Wants=network-online.target\n\n" +
    "[Service]\n" +
    "Type=oneshot\n" +
    env +
    `ExecStart=${[...argv, "ssh-guard", "heartbeat"].map(quote).join(" ")}\n` +
    "Nice=10\n" +
    "TimeoutStartSec=90\n";
  const timer =
    "# sandgate ssh-guard (managed)\n" +
    "[Unit]\n" +
    "Description=sandgate heartbeat every 5 minutes\n\n" +
    "[Timer]\n" +
    "OnBootSec=1min\n" +
    `OnUnitActiveSec=${HEARTBEAT_INTERVAL_SEC}s\n` +
    "RandomizedDelaySec=20s\n" +
    "AccuracySec=10s\n\n" +
    "[Install]\n" +
    "WantedBy=timers.target\n";
  return { service, timer };
}

function systemctl(...args: string[]): { ok: boolean; output: string } {
  try {
    return { ok: true, output: execFileSync("systemctl", args, { encoding: "utf8", stdio: "pipe", timeout: 30_000 }) };
  } catch (err: any) {
    return { ok: false, output: String(err?.stderr || err?.message || err).trim().slice(0, 300) };
  }
}

/** Install and start the timer. Never fatal: it only reports. */
export function installHeartbeat(argv: string[], configPath: string, defaultConfigPath: string): string {
  if (!existsSync("/run/systemd/system")) {
    return "heartbeat: no systemd here — run `sandgate ssh-guard heartbeat` from cron every 5 minutes instead";
  }
  const { service, timer } = heartbeatUnits(argv, configPath, defaultConfigPath);
  const same =
    existsSync(SERVICE_FILE) && existsSync(TIMER_FILE) &&
    readFileSync(SERVICE_FILE, "utf8") === service && readFileSync(TIMER_FILE, "utf8") === timer;
  if (!same) {
    writeFileSync(SERVICE_FILE, service);
    writeFileSync(TIMER_FILE, timer);
    systemctl("daemon-reload");
  }
  const started = systemctl("enable", "--now", "sandgate-heartbeat.timer");
  if (!started.ok) return `heartbeat: WARNING, the timer did not start: ${started.output}`;
  // The first beat now, not in 5 minutes: the phone shows the server
  // while you are still looking at it.
  systemctl("start", "--no-block", "sandgate-heartbeat.service");
  return "heartbeat: every 5 min to your phone (sandgate-heartbeat.timer)";
}

export function uninstallHeartbeat(): string | null {
  if (!existsSync(SERVICE_FILE) && !existsSync(TIMER_FILE)) return null;
  systemctl("disable", "--now", "sandgate-heartbeat.timer");
  rmSync(TIMER_FILE, { force: true });
  rmSync(SERVICE_FILE, { force: true });
  systemctl("daemon-reload");
  return "removed the heartbeat timer";
}
