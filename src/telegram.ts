import { randomBytes } from "node:crypto";

/**
 * MVP approval channel: a Telegram bot DM with Approve/Deny buttons.
 * Zero dependencies — plain Bot API over fetch, long-polling for the answer.
 * (The dedicated PWA with E2EE web push replaces this in a later release;
 * the Approver interface is what it will implement.)
 */

export interface ApprovalRequest {
  title: string;
  body?: string;
  timeoutSec: number;
}

export interface ApprovalResult {
  approved: boolean;
  decision: "approved" | "denied" | "timeout";
}

export interface Approver {
  request(req: ApprovalRequest): Promise<ApprovalResult>;
}

export class TelegramApprover implements Approver {
  constructor(
    private botToken: string,
    private chatId: string
  ) {}

  private async api(method: string, params: Record<string, unknown>) {
    const res = await fetch(
      `https://api.telegram.org/bot${this.botToken}/${method}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params),
      }
    );
    const json = (await res.json()) as { ok: boolean; result?: any; description?: string };
    if (!json.ok) throw new Error(`Telegram ${method} failed: ${json.description}`);
    return json.result;
  }

  async request(req: ApprovalRequest): Promise<ApprovalResult> {
    const nonce = randomBytes(8).toString("hex");
    const text =
      `🚪 *sandgate — approval requested*\n\n` +
      `*${escapeMd(req.title)}*` +
      (req.body ? `\n\n${escapeMd(req.body)}` : "") +
      `\n\n_No answer in ${req.timeoutSec}s = denied._`;

    const message = await this.api("sendMessage", {
      chat_id: this.chatId,
      text,
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "✅ Approve", callback_data: `ok:${nonce}` },
            { text: "❌ Deny", callback_data: `no:${nonce}` },
          ],
        ],
      },
    });

    const deadline = Date.now() + req.timeoutSec * 1000;
    let offset = 0;
    while (Date.now() < deadline) {
      const pollSec = Math.min(
        25,
        Math.max(1, Math.ceil((deadline - Date.now()) / 1000))
      );
      const updates: any[] = await this.api("getUpdates", {
        offset,
        timeout: pollSec,
        allowed_updates: ["callback_query"],
      });
      for (const update of updates) {
        offset = update.update_id + 1;
        const cb = update.callback_query;
        if (!cb?.data?.endsWith(`:${nonce}`)) continue;
        const approved = cb.data.startsWith("ok:");
        await this.api("answerCallbackQuery", { callback_query_id: cb.id });
        await this.api("editMessageText", {
          chat_id: this.chatId,
          message_id: message.message_id,
          text: text + (approved ? "\n\n✅ *Approved*" : "\n\n❌ *Denied*"),
          parse_mode: "Markdown",
        });
        return { approved, decision: approved ? "approved" : "denied" };
      }
    }

    await this.api("editMessageText", {
      chat_id: this.chatId,
      message_id: message.message_id,
      text: text + "\n\n⏱ *Timed out — denied*",
      parse_mode: "Markdown",
    }).catch(() => {});
    return { approved: false, decision: "timeout" };
  }
}

function escapeMd(s: string): string {
  return s.replace(/([_*`\[])/g, "\\$1");
}

/** Used by `sandgate init` to discover the chat id after the user messages the bot. */
export async function discoverChatId(botToken: string): Promise<string | null> {
  const res = await fetch(`https://api.telegram.org/bot${botToken}/getUpdates`);
  const json = (await res.json()) as { ok: boolean; result?: any[] };
  if (!json.ok || !json.result?.length) return null;
  for (const update of json.result.reverse()) {
    const id = update.message?.chat?.id;
    if (id) return String(id);
  }
  return null;
}
