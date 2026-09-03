import { randomBytes } from "node:crypto";

/**
 * MVP approval channel: a Telegram bot DM with Approve/Deny buttons.
 * Zero dependencies — plain Bot API over fetch, long-polling for answers.
 * A single dispatcher loop serves any number of concurrent approval
 * requests (Telegram allows only one getUpdates consumer per bot), so
 * several agents can be waiting on the human at once.
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

export interface AskResult {
  answer: string | null;
  decision: "answered" | "denied" | "timeout";
}

export interface Approver {
  request(req: ApprovalRequest): Promise<ApprovalResult>;
  /**
   * Free-text question to the human (SMS codes, security questions,
   * choices). Optional: the PWA channel implements it; Telegram does not.
   */
  ask?(req: ApprovalRequest): Promise<AskResult>;
}

interface PendingApproval {
  resolve: (result: ApprovalResult) => void;
  messageId: number;
  text: string;
  deadline: number;
}

// Telegram messages cap at 4096 chars; keep agent-supplied text well under.
const MAX_FIELD = 1000;

export class TelegramApprover implements Approver {
  private pending = new Map<string, PendingApproval>();
  private polling = false;
  private offset = 0;

  constructor(
    private botToken: string,
    private chatId: string
  ) {}

  /** Overridable in tests. */
  protected async api(method: string, params: Record<string, unknown>): Promise<any> {
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
      `*sandgate — approval requested*\n\n` +
      `*${escapeMd(req.title.slice(0, MAX_FIELD))}*` +
      (req.body ? `\n\n${escapeMd(req.body.slice(0, MAX_FIELD))}` : "") +
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

    return new Promise<ApprovalResult>((resolve) => {
      this.pending.set(nonce, {
        resolve,
        messageId: message.message_id,
        text,
        deadline: Date.now() + req.timeoutSec * 1000,
      });
      void this.runDispatcher();
    });
  }

  private settle(nonce: string, entry: PendingApproval, result: ApprovalResult, suffix: string) {
    this.pending.delete(nonce);
    void this.api("editMessageText", {
      chat_id: this.chatId,
      message_id: entry.messageId,
      text: entry.text + `\n\n${suffix}`,
      parse_mode: "Markdown",
    }).catch(() => {});
    entry.resolve(result);
  }

  private async runDispatcher(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      while (this.pending.size > 0) {
        const now = Date.now();
        for (const [nonce, entry] of [...this.pending]) {
          if (now >= entry.deadline) {
            this.settle(nonce, entry, { approved: false, decision: "timeout" }, "⏱ *Timed out — denied*");
          }
        }
        if (this.pending.size === 0) break;

        const soonest = Math.min(...[...this.pending.values()].map((p) => p.deadline));
        const pollSec = Math.min(10, Math.max(1, Math.ceil((soonest - Date.now()) / 1000)));
        let updates: any[];
        try {
          updates = await this.api("getUpdates", {
            offset: this.offset,
            timeout: pollSec,
            allowed_updates: ["callback_query"],
          });
        } catch {
          await new Promise((r) => setTimeout(r, 2000)); // transient network/API error
          continue;
        }

        for (const update of updates) {
          this.offset = update.update_id + 1;
          const cb = update.callback_query;
          if (!cb?.data) continue;
          const [verdict, nonce] = String(cb.data).split(":");
          const entry = nonce ? this.pending.get(nonce) : undefined;
          if (!entry) continue;
          // Only accept taps on our message in our chat.
          if (String(cb.message?.chat?.id ?? "") !== String(this.chatId)) continue;
          const approved = verdict === "ok";
          await this.api("answerCallbackQuery", { callback_query_id: cb.id }).catch(() => {});
          this.settle(
            nonce!,
            entry,
            { approved, decision: approved ? "approved" : "denied" },
            approved ? "✅ *Approved*" : "❌ *Denied*"
          );
        }
      }
    } finally {
      this.polling = false;
      // A request may have landed while we were shutting down.
      if (this.pending.size > 0) void this.runDispatcher();
    }
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
