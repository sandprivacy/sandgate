import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveRelayUrl, HOSTED_RELAY } from "../relay-default.js";

test("pair picks the hosted relay unless told otherwise", () => {
  assert.deepEqual(resolveRelayUrl(undefined, {}), { url: HOSTED_RELAY, source: "hosted" });
  // An explicit argument always wins, trailing slash dropped.
  assert.deepEqual(resolveRelayUrl("https://relay.example/", { SANDGATE_RELAY: "https://other" }), {
    url: "https://relay.example",
    source: "argument",
  });
  // The environment makes self-hosting the default for good.
  assert.deepEqual(resolveRelayUrl(undefined, { SANDGATE_RELAY: "http://localhost:8787/" }), {
    url: "http://localhost:8787",
    source: "env",
  });
  assert.deepEqual(resolveRelayUrl("  ", { SANDGATE_RELAY: "  " }), { url: HOSTED_RELAY, source: "hosted" });
});
