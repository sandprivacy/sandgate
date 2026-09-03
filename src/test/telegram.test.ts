import { test } from "node:test";
import assert from "node:assert/strict";
import { TelegramApprover } from "../telegram.js";

/**
 * Fake transport: captures sent messages, then feeds callback taps to the
 * dispatcher. Lets us prove several concurrent approvals resolve correctly
 * through the single getUpdates loop.
 */
class FakeTelegram extends TelegramApprover {
  sent: { messageId: number; nonce: string }[] = [];
  taps: { verdict: "ok" | "no"; nonce: string }[] = [];
  private nextMessageId = 1;
  private nextUpdateId = 1;

  constructor() {
    super("fake-token", "12345");
  }

  protected override async api(method: string, params: any): Promise<any> {
    if (method === "sendMessage") {
      const nonce = params.reply_markup.inline_keyboard[0][0].callback_data.split(":")[1];
      const messageId = this.nextMessageId++;
      this.sent.push({ messageId, nonce });
      return { message_id: messageId };
    }
    if (method === "getUpdates") {
      await new Promise((r) => setTimeout(r, 10));
      const updates = this.taps.map((tap) => ({
        update_id: this.nextUpdateId++,
        callback_query: {
          id: "cb" + this.nextUpdateId,
          data: `${tap.verdict}:${tap.nonce}`,
          message: { chat: { id: 12345 } },
        },
      }));
      this.taps = [];
      return updates;
    }
    return {}; // answerCallbackQuery, editMessageText
  }
}

test("two concurrent approvals resolve independently through one dispatcher", async () => {
  const fake = new FakeTelegram();
  const a = fake.request({ title: "Payment A", timeoutSec: 5 });
  const b = fake.request({ title: "Payment B", timeoutSec: 5 });

  // Wait until both messages are sent, then tap: deny A, approve B.
  while (fake.sent.length < 2) await new Promise((r) => setTimeout(r, 5));
  fake.taps.push({ verdict: "no", nonce: fake.sent[0].nonce });
  fake.taps.push({ verdict: "ok", nonce: fake.sent[1].nonce });

  const [ra, rb] = await Promise.all([a, b]);
  assert.deepEqual(ra, { approved: false, decision: "denied" });
  assert.deepEqual(rb, { approved: true, decision: "approved" });
});

test("a tap from a foreign chat is ignored, and the request times out", async () => {
  class ForeignChat extends FakeTelegram {
    protected override async api(method: string, params: any): Promise<any> {
      if (method === "getUpdates" && this.sent.length) {
        await new Promise((r) => setTimeout(r, 10));
        return [
          {
            update_id: 999,
            callback_query: {
              id: "cb999",
              data: `ok:${this.sent[0].nonce}`,
              message: { chat: { id: 666 } }, // wrong chat
            },
          },
        ];
      }
      return super.api(method, params);
    }
  }
  const fake = new ForeignChat();
  const result = await fake.request({ title: "Sensitive", timeoutSec: 1 });
  assert.equal(result.decision, "timeout");
  assert.equal(result.approved, false);
});

test("unanswered requests time out as denied", async () => {
  const fake = new FakeTelegram();
  const result = await fake.request({ title: "Silence", timeoutSec: 1 });
  assert.deepEqual(result, { approved: false, decision: "timeout" });
});
