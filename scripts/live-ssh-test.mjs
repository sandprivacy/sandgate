// Live end-to-end check of ssh-guard against a real server.
// Plays the phone from here: polls the relay, decrypts what the server
// asked, answers it — exactly what the PWA does on a phone.
//
// Usage: node scripts/live-ssh-test.mjs <approve|deny|ignore>
import { spawn } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const dist = (f) => pathToFileURL(join(process.cwd(), "dist", f)).href;
const { deriveKey, seal, open, aadForRequest, aadForDecision } = await import(dist("pwacrypto.js"));

const { SG_RELAY, SG_PAIR_ID, SG_SECRET, SG_HOST, SG_PASSWORD } = process.env;
const ANSWER = process.argv[2];
const key = deriveKey(SG_SECRET);

async function playPhone(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const items = await (await fetch(`${SG_RELAY}/api/pending?pairId=${SG_PAIR_ID}`)).json();
    if (items.length) {
      const { requestId, payload } = items[0];
      const request = open(key, payload, aadForRequest(requestId));
      console.log(`  [phone] "${request.title}" — ${request.body ?? ""}`);
      if (ANSWER === "ignore") {
        console.log("  [phone] deliberately ignoring it");
        return request;
      }
      const approved = ANSWER === "approve";
      await fetch(`${SG_RELAY}/api/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairId: SG_PAIR_ID,
          requestId,
          payload: seal(key, { requestId, approved, ts: Date.now() }, aadForDecision(requestId)),
        }),
      });
      console.log(`  [phone] tapped ${approved ? "Approve" : "Deny"}`);
      return request;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  console.log("  [phone] nothing ever arrived");
  return null;
}

function sshLogin() {
  return new Promise((resolve) => {
    const started = Date.now();
    // The guard turns sshd into keyboard-interactive, so -pw is not enough:
    // the password has to be typed at the prompt. Feed it in.
    const child = spawn("plink", [`root@${SG_HOST}`, "echo LOGIN_OK"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    let sent = false;
    const maybeAnswer = (text) => {
      if (!sent && /password/i.test(text)) {
        sent = true;
        child.stdin.write(SG_PASSWORD + "\n");
      }
    };
    child.stdout.on("data", (d) => { out += d; maybeAnswer(String(d)); });
    child.stderr.on("data", (d) => { err += d; maybeAnswer(String(d)); });
    child.on("close", () =>
      resolve({
        ok: out.includes("LOGIN_OK"),
        seconds: Math.round((Date.now() - started) / 1000),
        err: err.trim().split("\n").filter(Boolean).pop(),
      })
    );
  });
}

console.log(`\n=== login with the phone answering: ${ANSWER} ===`);
const [login, request] = await Promise.all([sshLogin(), playPhone(60000)]);
console.log(`  [ssh]   ${login.ok ? "LOGGED IN" : "REFUSED"} after ${login.seconds}s${login.ok ? "" : ` — ${login.err}`}`);
console.log(request ? "  => the guard was consulted first" : "  => WARNING: the guard was bypassed");
process.exit(0);
