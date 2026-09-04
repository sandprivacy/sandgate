import { test } from "node:test";
import assert from "node:assert/strict";
import { SlackApprover, verifySlack, type SlackSocket, type SlackTransport } from "../slack.js";

/**
 * The Slack channel, driven end to end against a fake Slack: what gets
 * posted, which taps count, how the message is settled. Socket Mode is
 * replaced by a socket the test feeds envelopes into.
 */

function fakeSlack() {
  const calls: { method: string; body: any }[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    const method = url.split("/api/")[1]!;
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    calls.push({ method, body });
    const reply: Record<string, unknown> = { ok: true };
    if (method === "chat.postMessage") Object.assign(reply, { ts: "1700000000.000100", channel: "C123" });
    if (method === "auth.test") Object.assign(reply, { team: "acme", user: "sandgate" });
    if (method === "conversations.list") Object.assign(reply, { channels: [{ id: "C777", name: "approvals" }] });
    return { json: async () => reply } as Response;
  };

  let handler: ((text: string) => void) | null = null;
  const sent: any[] = [];
  let closed = false;
  const socket: SlackSocket = {
    send: (text) => sent.push(JSON.parse(text)),
    onMessage: (cb) => (handler = cb),
    close: () => (closed = true),
  };
  const transport: SlackTransport = { open: async () => socket };
  const deliver = (payload: unknown, envelopeId = "env-" + sent.length) =>
    handler!(JSON.stringify({ type: "interactive", envelope_id: envelopeId, payload }));
  const tap = (userId: string, actionId: string, value: string) =>
    deliver({ type: "block_actions", user: { id: userId }, trigger_id: "trig", actions: [{ action_id: actionId, value }] });
  const requestIdFromPost = () =>
    calls.find((c) => c.method === "chat.postMessage")!.body.blocks[1].elements[0].value as string;
  return { fetchImpl, transport, calls, sent, deliver, tap, requestIdFromPost, isClosed: () => closed };
}

async function settle() {
  await new Promise((r) => setTimeout(r, 20));
}

test("a tap on Approve by a listed approver approves; the message records who", async () => {
  const slack = fakeSlack();
  const approver = new SlackApprover(
    { botToken: "xoxb", appToken: "xapp", channel: "C123", approvers: ["U_ALICE"] },
    { transport: slack.transport, fetchImpl: slack.fetchImpl }
  );
  const pending = approver.request({ title: "Deploy v2", body: "to production", timeoutSec: 5 });
  await settle();
  const requestId = slack.requestIdFromPost();
  assert.match(slack.calls[0]!.body.blocks[0].text.text, /Deploy v2/);

  // Someone who is not an approver taps first: nothing happens.
  slack.tap("U_MALLORY", "sandgate_approve", requestId);
  await settle();
  // A tap on a different request's button is not ours either.
  slack.tap("U_ALICE", "sandgate_approve", "some-other-id");
  await settle();
  slack.tap("U_ALICE", "sandgate_approve", requestId);

  assert.deepEqual(await pending, { approved: true, decision: "approved" });
  // Every envelope acknowledged, whoever sent it — or Slack resends.
  assert.equal(slack.sent.length, 3);
  assert.ok(slack.sent.every((s) => typeof s.envelope_id === "string"));
  const update = slack.calls.find((c) => c.method === "chat.update")!;
  assert.match(update.body.text, /Approved by <@U_ALICE>/);
  assert.ok(slack.isClosed(), "the socket is released after the decision");
});

test("Deny refuses, and a quorum needs distinct approvers", async () => {
  const slack = fakeSlack();
  const approver = new SlackApprover(
    { botToken: "xoxb", appToken: "xapp", channel: "C123", quorum: 2 },
    { transport: slack.transport, fetchImpl: slack.fetchImpl }
  );
  const pending = approver.request({ title: "Wire funds", timeoutSec: 5 });
  await settle();
  const requestId = slack.requestIdFromPost();
  assert.match(slack.calls[0]!.body.blocks[0].text.text, /2 approvers must agree/);
  slack.tap("U_A", "sandgate_approve", requestId);
  slack.tap("U_A", "sandgate_approve", requestId); // same person twice: still one
  await settle();
  slack.tap("U_B", "sandgate_deny", requestId);
  assert.deepEqual(await pending, { approved: false, decision: "denied" });
  assert.match(slack.calls.find((c) => c.method === "chat.update")!.body.text, /Denied by <@U_B>/);
});

test("a typed answer comes back through the modal", async () => {
  const slack = fakeSlack();
  const approver = new SlackApprover(
    { botToken: "xoxb", appToken: "xapp", channel: "C123" },
    { transport: slack.transport, fetchImpl: slack.fetchImpl }
  );
  const pending = approver.ask!({ title: "SMS code for the bank?", timeoutSec: 5 });
  await settle();
  const requestId = slack.requestIdFromPost();
  slack.tap("U_A", "sandgate_answer", requestId);
  await settle();
  const modal = slack.calls.find((c) => c.method === "views.open")!;
  assert.equal(modal.body.view.private_metadata, requestId, "the modal carries our request id back");
  slack.deliver({
    type: "view_submission",
    user: { id: "U_A" },
    view: { private_metadata: requestId, state: { values: { answer: { value: { value: " 482913 " } } } } },
  });
  assert.deepEqual(await pending, { answer: "482913", decision: "answered" });
});

test("silence expires, and says so in the channel", async () => {
  const slack = fakeSlack();
  const approver = new SlackApprover(
    { botToken: "xoxb", appToken: "xapp", channel: "C123" },
    { transport: slack.transport, fetchImpl: slack.fetchImpl }
  );
  const result = await approver.request({ title: "Nobody home", timeoutSec: 0.2 });
  assert.deepEqual(result, { approved: false, decision: "timeout" });
  assert.match(slack.calls.find((c) => c.method === "chat.update")!.body.text, /Expired/);
});

test("connect-slack checks both tokens and resolves a channel name", async () => {
  const slack = fakeSlack();
  const info = await verifySlack({ botToken: "xoxb", appToken: "xapp", channel: "#approvals" }, slack.fetchImpl);
  assert.deepEqual(info, { team: "acme", bot: "sandgate", channelId: "C777" });
  await assert.rejects(
    verifySlack({ botToken: "xoxb", appToken: "xapp", channel: "#nowhere" }, slack.fetchImpl),
    /No channel named #nowhere/
  );
});
