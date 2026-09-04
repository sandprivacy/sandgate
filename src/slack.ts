import { randomBytes } from "node:crypto";
import type { Approver, ApprovalRequest, ApprovalResult, AskResult } from "./telegram.js";

/**
 * Approvals in a Slack channel, for teams: the request is a message with
 * Approve / Deny buttons, a typed answer comes through a modal, and the
 * result is written back into the message so the channel keeps the
 * record. Only listed approvers count; anyone else's tap is ignored.
 *
 * Transport is Socket Mode — the gateway opens a WebSocket to Slack, so
 * nothing needs a public URL. That needs a global WebSocket (Node 22+).
 *
 * Unlike the phone channel, Slack sees the request text. That is the
 * point of a shared channel; it is also why a personal secret still goes
 * to the phone.
 */

export interface SlackConfig {
  /** xoxb- bot token: chat:write, chat:write.public (optional), users:read (optional). */
  botToken: string;
  /** xapp- app-level token with connections:write, for Socket Mode. */
  appToken: string;
  /** Channel id (C…) or name the bot was invited to. */
  channel: string;
  /** Slack user ids allowed to decide. Empty: anyone in the channel. */
  approvers?: string[];
  /** Distinct approvers that must say yes (default 1). One Deny refuses. */
  quorum?: number;
}

/** What a Socket Mode connection looks like to this module; tests fake it. */
export interface SlackSocket {
  send(text: string): void;
  onMessage(cb: (text: string) => void): void;
  close(): void;
}

export interface SlackTransport {
  open(appToken: string): Promise<SlackSocket>;
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** The default transport: apps.connections.open, then the browser-style WebSocket Node ships. */
export const socketModeTransport: SlackTransport = {
  async open(appToken) {
    const res = await fetch("https://slack.com/api/apps.connections.open", {
      method: "POST",
      headers: { Authorization: `Bearer ${appToken}`, "Content-Type": "application/x-www-form-urlencoded" },
    });
    const body = (await res.json()) as { ok: boolean; url?: string; error?: string };
    if (!body.ok || !body.url) throw new Error(`Slack Socket Mode refused: ${body.error ?? "no url"}`);
    const WS = (globalThis as any).WebSocket;
    if (!WS) throw new Error("The Slack channel needs a global WebSocket (Node 22 or newer).");
    const ws = new WS(body.url);
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => resolve());
      ws.addEventListener("error", (e: any) => reject(new Error(`Slack socket error: ${e?.message ?? e}`)));
    });
    return {
      send: (text) => ws.send(text),
      onMessage: (cb) => ws.addEventListener("message", (e: any) => cb(String(e.data))),
      close: () => ws.close(),
    };
  },
};

/**
 * The title and body are written by whatever is asking — an agent under
 * prompt injection included. In mrkdwn, "<!channel>" pages everyone and
 * "<@U…>" impersonates a mention; neither may come from a request.
 */
export function escapeMrkdwn(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export class SlackApprover implements Approver {
  private transport: SlackTransport;
  private fetchImpl: FetchLike;

  constructor(
    private config: SlackConfig,
    deps: { transport?: SlackTransport; fetchImpl?: FetchLike } = {}
  ) {
    this.transport = deps.transport ?? socketModeTransport;
    this.fetchImpl = deps.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  private async api(method: string, payload: Record<string, unknown>): Promise<any> {
    const res = await this.fetchImpl(`https://slack.com/api/${method}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.config.botToken}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000),
    });
    const body = (await res.json()) as { ok: boolean; error?: string; [k: string]: unknown };
    if (!body.ok) throw new Error(`Slack ${method} failed: ${body.error ?? "unknown error"}`);
    return body;
  }

  private allowed(userId: string): boolean {
    const list = this.config.approvers ?? [];
    return list.length === 0 || list.includes(userId);
  }

  private blocks(requestId: string, req: ApprovalRequest, kind: "approval" | "input") {
    const quorum = kind === "approval" ? Math.max(1, this.config.quorum ?? 1) : 1;
    const text = [`*${escapeMrkdwn(req.title)}*`, escapeMrkdwn(req.body ?? ""), quorum > 1 ? `_${quorum} approvers must agree._` : ""]
      .filter(Boolean)
      .join("\n");
    const actions =
      kind === "approval"
        ? [
            { type: "button", style: "primary", text: { type: "plain_text", text: "Approve" }, action_id: "sandgate_approve", value: requestId },
            { type: "button", style: "danger", text: { type: "plain_text", text: "Deny" }, action_id: "sandgate_deny", value: requestId },
          ]
        : [
            { type: "button", style: "primary", text: { type: "plain_text", text: "Answer" }, action_id: "sandgate_answer", value: requestId },
            { type: "button", style: "danger", text: { type: "plain_text", text: "Decline" }, action_id: "sandgate_deny", value: requestId },
          ];
    return [
      { type: "section", text: { type: "mrkdwn", text } },
      { type: "actions", block_id: `sandgate_${requestId}`, elements: actions },
      { type: "context", elements: [{ type: "mrkdwn", text: `sandgate · expires in ${req.timeoutSec}s` }] },
    ];
  }

  /** Post, listen, settle. One socket per request keeps the code honest and the failure modes obvious. */
  private async roundTrip(
    kind: "approval" | "input",
    req: ApprovalRequest
  ): Promise<{ approved: boolean; answer?: string; decision: "approved" | "denied" | "timeout"; by: string[] }> {
    const requestId = randomBytes(12).toString("base64url");
    const quorum = kind === "approval" ? Math.max(1, this.config.quorum ?? 1) : 1;
    const posted = await this.api("chat.postMessage", {
      channel: this.config.channel,
      text: req.title,
      blocks: this.blocks(requestId, req, kind),
    });
    const ts = posted.ts as string;
    const channel = (posted.channel as string) ?? this.config.channel;

    const socket = await this.transport.open(this.config.appToken);
    const approvedBy = new Set<string>();
    let settled = false;

    const outcome = await new Promise<{ approved: boolean; answer?: string; decision: "approved" | "denied" | "timeout"; by: string[] }>((resolve) => {
      const timer = setTimeout(() => finish({ approved: false, decision: "timeout", by: [...approvedBy] }), req.timeoutSec * 1000);
      const finish = (result: { approved: boolean; answer?: string; decision: "approved" | "denied" | "timeout"; by: string[] }) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      };

      socket.onMessage((text) => {
        let msg: any;
        try {
          msg = JSON.parse(text);
        } catch {
          return;
        }
        // Every envelope must be acknowledged within 3s or Slack resends it.
        if (msg.envelope_id) socket.send(JSON.stringify({ envelope_id: msg.envelope_id }));
        if (msg.type !== "interactive" || !msg.payload) return;
        const payload = msg.payload;
        const user: string = payload.user?.id ?? "";

        if (payload.type === "block_actions") {
          const action = (payload.actions ?? []).find((a: any) => typeof a.value === "string" && a.value === requestId);
          if (!action) return;
          if (!this.allowed(user)) return; // not an approver: their tap changes nothing
          if (action.action_id === "sandgate_deny") return finish({ approved: false, decision: "denied", by: [user] });
          if (action.action_id === "sandgate_approve") {
            approvedBy.add(user);
            if (approvedBy.size >= quorum) finish({ approved: true, decision: "approved", by: [...approvedBy] });
            return;
          }
          if (action.action_id === "sandgate_answer" && payload.trigger_id) {
            // Their answer comes back as a view_submission carrying our id.
            this.api("views.open", {
              trigger_id: payload.trigger_id,
              view: {
                type: "modal",
                callback_id: "sandgate_answer_modal",
                private_metadata: requestId,
                title: { type: "plain_text", text: "sandgate" },
                submit: { type: "plain_text", text: "Send" },
                close: { type: "plain_text", text: "Cancel" },
                blocks: [
                  { type: "section", text: { type: "mrkdwn", text: `*${escapeMrkdwn(req.title)}*${req.body ? "\n" + escapeMrkdwn(req.body) : ""}` } },
                  {
                    type: "input",
                    block_id: "answer",
                    label: { type: "plain_text", text: "Your answer" },
                    element: { type: "plain_text_input", action_id: "value" },
                  },
                ],
              },
            }).catch(() => {});
          }
          return;
        }
        if (payload.type === "view_submission" && payload.view?.private_metadata === requestId) {
          if (!this.allowed(user)) return;
          const answer = payload.view?.state?.values?.answer?.value?.value;
          if (typeof answer === "string" && answer.trim()) {
            finish({ approved: true, answer: answer.trim(), decision: "approved", by: [user] });
          }
        }
      });
    });

    socket.close();
    // Leave the record in the channel: who decided, or that nobody did.
    const verdict =
      outcome.decision === "approved"
        ? `Approved by ${outcome.by.map((u) => `<@${u}>`).join(", ")}`
        : outcome.decision === "denied"
          ? `Denied by <@${outcome.by[0]}>`
          : "Expired without a decision";
    await this.api("chat.update", {
      channel,
      ts,
      text: `${req.title} — ${verdict}`,
      blocks: [
        { type: "section", text: { type: "mrkdwn", text: `*${escapeMrkdwn(req.title)}*${req.body ? "\n" + escapeMrkdwn(req.body) : ""}` } },
        { type: "context", elements: [{ type: "mrkdwn", text: `sandgate · ${verdict}` }] },
      ],
    }).catch(() => {});
    return outcome;
  }

  async request(req: ApprovalRequest): Promise<ApprovalResult> {
    const r = await this.roundTrip("approval", req);
    return { approved: r.approved, decision: r.decision };
  }

  async ask(req: ApprovalRequest): Promise<AskResult> {
    const r = await this.roundTrip("input", req);
    if (r.decision === "approved" && typeof r.answer === "string") return { answer: r.answer, decision: "answered" };
    return { answer: null, decision: r.decision === "denied" ? "denied" : "timeout" };
  }
}

/** Confirm the tokens work and resolve a #channel name to its id. */
export async function verifySlack(
  config: Pick<SlackConfig, "botToken" | "appToken" | "channel">,
  fetchImpl: FetchLike = (i, init) => fetch(i, init)
): Promise<{ team: string; bot: string; channelId: string }> {
  const call = async (token: string, method: string, body?: Record<string, unknown>) => {
    const res = await fetchImpl(`https://slack.com/api/${method}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(body ?? {}),
      signal: AbortSignal.timeout(15_000),
    });
    const json = (await res.json()) as any;
    if (!json.ok) throw new Error(`Slack ${method} failed: ${json.error ?? "unknown error"}`);
    return json;
  };
  const auth = await call(config.botToken, "auth.test");
  await call(config.appToken, "apps.connections.open");
  let channelId = config.channel;
  if (!/^[CG][A-Z0-9]+$/.test(channelId)) {
    const wanted = channelId.replace(/^#/, "");
    const list = await call(config.botToken, "conversations.list", { limit: 1000, types: "public_channel,private_channel" });
    const hit = (list.channels as any[]).find((c) => c.name === wanted);
    if (!hit) throw new Error(`No channel named #${wanted} is visible to the bot. Invite it first: /invite @${auth.user}`);
    channelId = hit.id;
  }
  return { team: auth.team as string, bot: auth.user as string, channelId };
}
