import { test } from "node:test";
import assert from "node:assert/strict";
import { resolvePassphrase } from "../passphrase.js";

test("direct SANDGATE_PASSPHRASE wins", () => {
  assert.equal(
    resolvePassphrase({ SANDGATE_PASSPHRASE: "direct", SANDGATE_PASSPHRASE_CMD: "echo nope" }),
    "direct"
  );
});

test("SANDGATE_PASSPHRASE_CMD output is used, trimmed", () => {
  const cmd = `node -e "console.log('  from-command  ')"`;
  assert.equal(resolvePassphrase({ SANDGATE_PASSPHRASE_CMD: cmd }), "from-command");
});

test("empty command output resolves to undefined", () => {
  const cmd = `node -e "console.log('')"`;
  assert.equal(resolvePassphrase({ SANDGATE_PASSPHRASE_CMD: cmd }), undefined);
});

test("neither variable set resolves to undefined", () => {
  assert.equal(resolvePassphrase({}), undefined);
});

test("a failing command throws", () => {
  assert.throws(() => resolvePassphrase({ SANDGATE_PASSPHRASE_CMD: `node -e "process.exit(3)"` }));
});
