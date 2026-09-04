import type { Approver } from "./telegram.js";
import { TelegramApprover } from "./telegram.js";
import { SlackApprover } from "./slack.js";
import { pwaApproverFrom } from "./pwa-approver.js";
import type { VaultData } from "./vault.js";
import type { Config } from "./config.js";

/**
 * One place that decides where a request goes. Every path that asks a
 * human — the MCP server, `sandgate ask`, `test-approval` — comes here,
 * so they cannot disagree about it (they once did, and the CLI silently
 * lost biometric enforcement).
 *
 * Order when nothing is chosen: the phone (private, end-to-end), then
 * Slack (a team), then Telegram (the original channel).
 */

export type ChannelName = "phone" | "slack" | "telegram";

export function availableChannels(vault: VaultData): ChannelName[] {
  const out: ChannelName[] = [];
  if (vault.pwa) out.push("phone");
  if (vault.slack) out.push("slack");
  if (vault.telegram) out.push("telegram");
  return out;
}

export function chooseChannel(vault: VaultData, config: Config): ChannelName | null {
  const available = availableChannels(vault);
  if (config.approvalChannel && available.includes(config.approvalChannel)) {
    return config.approvalChannel;
  }
  return available[0] ?? null;
}

export function approverFor(vault: VaultData, config: Config): Approver | null {
  switch (chooseChannel(vault, config)) {
    case "phone":
      return pwaApproverFrom(vault, config);
    case "slack":
      return new SlackApprover({ ...vault.slack!, quorum: vault.slack!.quorum });
    case "telegram":
      return new TelegramApprover(vault.telegram!.botToken, vault.telegram!.chatId);
    default:
      return null;
  }
}

export function describeChannel(vault: VaultData, config: Config): string {
  const chosen = chooseChannel(vault, config);
  const others = availableChannels(vault).filter((c) => c !== chosen);
  const label = (c: ChannelName) =>
    c === "phone"
      ? `phone via ${vault.pwa!.relayUrl}${(vault.pwa!.quorum ?? 1) > 1 ? ` (quorum ${vault.pwa!.quorum})` : ""}`
      : c === "slack"
        ? `Slack ${vault.slack!.channel}${(vault.slack!.quorum ?? 1) > 1 ? ` (quorum ${vault.slack!.quorum})` : ""}`
        : "Telegram";
  if (!chosen) return "none — run `sandgate pair <relay-url>`, `sandgate connect-slack …` or `sandgate connect-telegram <token>`";
  return label(chosen) + (others.length ? ` (also configured: ${others.join(", ")} — switch with \`sandgate channel <name>\`)` : "");
}
