import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { newPairing } from "../pwacrypto.js";
import { startRelay } from "../relay/server.js";
import { PwaApprover } from "../pwa-approver.js";
import { loadPage, waitFor } from "./helpers/page.js";

/**
 * Browser-level biometric tests: the real page script runs the real
 * WebAuthn ceremonies against a simulated platform authenticator (same
 * key type, same signed payload as a Face ID enclave), and the real
 * gateway verifies the result. Covers enrollment, a genuine approval,
 * and — the one that matters — an authenticator that is not the enrolled
 * one being rejected.
 */

function b64u(buf: Buffer | Uint8Array | ArrayBuffer): string {
  return Buffer.from(buf as any).toString("base64url");
}

/** Install a fake platform authenticator into a jsdom window. */
function installAuthenticator(
  window: any,
  opts: { signingKey: KeyObject; publicKeySpki: Buffer; credentialId: Buffer }
) {
  const origin = window.location.origin;
  const rpIdHash = createHash("sha256").update(window.location.hostname).digest();

  const clientData = (type: string, challenge: ArrayBuffer) =>
    Buffer.from(
      JSON.stringify({ type, challenge: b64u(challenge), origin }),
      "utf8"
    );

  window.PublicKeyCredential = function () {};
  Object.defineProperty(window.navigator, "credentials", {
    configurable: true,
    value: {
      async create(request: any) {
        const cd = clientData("webauthn.create", request.publicKey.challenge);
        return {
          rawId: opts.credentialId,
          response: {
            clientDataJSON: cd,
            getPublicKey: () => opts.publicKeySpki,
          },
        };
      },
      async get(request: any) {
        const cd = clientData("webauthn.get", request.publicKey.challenge);
        const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.alloc(4)]);
        const signed = Buffer.concat([authData, createHash("sha256").update(cd).digest()]);
        return {
          rawId: opts.credentialId,
          response: {
            authenticatorData: authData,
            clientDataJSON: cd,
            signature: cryptoSign("sha256", signed, opts.signingKey),
          },
        };
      },
    },
  });
}

function keypair() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    signingKey: privateKey,
    publicKeySpki: publicKey.export({ format: "der", type: "spki" }) as Buffer,
  };
}

async function withRelay<T>(fn: (relayUrl: string) => Promise<T>): Promise<T> {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  try {
    return await fn(`http://localhost:${relay.port}`);
  } finally {
    relay.close();
  }
}

test("enrollment through the page yields a credential the gateway trusts", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const { window, alerts, close } = await loadPage(relayUrl, {
      hash: `#p=${pairing.pairId}&s=${pairing.secret}`,
    });
    try {
      const device = keypair();
      installAuthenticator(window, { ...device, credentialId: Buffer.from("cred-1") });

      const approver = new PwaApprover({ relayUrl, pairId: pairing.pairId, secret: pairing.secret });
      const enrolling = approver.enroll(20);

      const enableBtn = await waitFor(() => window.document.querySelector(".card button.ok"));
      assert.match(window.document.querySelector(".card .who").textContent, /setup/);
      enableBtn.click();

      const credential = await enrolling;
      assert.ok(credential, "enrollment returned nothing");
      assert.equal(credential!.rpId, "localhost");
      assert.equal(credential!.publicKeySpki, b64u(device.publicKeySpki));
      assert.deepEqual(alerts, [], `page alerted: ${alerts.join(" | ")}`);
    } finally {
      close();
    }
  });
});

test("with biometrics required, an approval signed by the enrolled device is accepted", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const device = keypair();
    const credentialId = Buffer.from("cred-1");

    // 1. Enroll.
    const enrollPage = await loadPage(relayUrl, { hash: `#p=${pairing.pairId}&s=${pairing.secret}` });
    installAuthenticator(enrollPage.window, { ...device, credentialId });
    const enroller = new PwaApprover({ relayUrl, pairId: pairing.pairId, secret: pairing.secret });
    const enrolling = enroller.enroll(20);
    (await waitFor(() => enrollPage.window.document.querySelector(".card button.ok"))).click();
    const credential = await enrolling;
    enrollPage.close();
    assert.ok(credential);

    // 2. Approve, biometrics enforced.
    const page = await loadPage(relayUrl, { hash: `#p=${pairing.pairId}&s=${pairing.secret}` });
    installAuthenticator(page.window, { ...device, credentialId });
    try {
      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
        biometric: credential!,
        requireBiometric: true,
      });
      const deciding = approver.request({ title: "Pay 300 EUR", timeoutSec: 20 });

      const approveBtn = await waitFor(() => page.window.document.querySelector(".card button.ok"));
      assert.match(approveBtn.textContent, /Face ID/);
      approveBtn.click();

      assert.deepEqual(await deciding, { approved: true, decision: "approved" });
      assert.deepEqual(page.alerts, [], `page alerted: ${page.alerts.join(" | ")}`);
    } finally {
      page.close();
    }
  });
});

test("an approval signed by a different authenticator is refused, fail closed", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const enrolledDevice = keypair();
    const credentialId = Buffer.from("cred-1");

    const enrollPage = await loadPage(relayUrl, { hash: `#p=${pairing.pairId}&s=${pairing.secret}` });
    installAuthenticator(enrollPage.window, { ...enrolledDevice, credentialId });
    const enroller = new PwaApprover({ relayUrl, pairId: pairing.pairId, secret: pairing.secret });
    const enrolling = enroller.enroll(20);
    (await waitFor(() => enrollPage.window.document.querySelector(".card button.ok"))).click();
    const credential = await enrolling;
    enrollPage.close();

    // The phone now signs with someone else's key — a stolen page, a
    // tampered client. The gateway must not accept it as an approval.
    const page = await loadPage(relayUrl, { hash: `#p=${pairing.pairId}&s=${pairing.secret}` });
    installAuthenticator(page.window, { ...keypair(), credentialId });
    try {
      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
        biometric: credential!,
        requireBiometric: true,
      });
      const deciding = approver.request({ title: "Pay 300 EUR", timeoutSec: 20 });
      (await waitFor(() => page.window.document.querySelector(".card button.ok"))).click();
      await assert.rejects(deciding, /does not verify/);
    } finally {
      page.close();
    }
  });
});

test("with biometrics required, a typed answer is signed too — and accepted", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const device = keypair();
    const credentialId = Buffer.from("cred-2");

    const enrollPage = await loadPage(relayUrl, { hash: `#p=${pairing.pairId}&s=${pairing.secret}` });
    installAuthenticator(enrollPage.window, { ...device, credentialId });
    const enroller = new PwaApprover({ relayUrl, pairId: pairing.pairId, secret: pairing.secret });
    const enrolling = enroller.enroll(20);
    (await waitFor(() => enrollPage.window.document.querySelector(".card button.ok"))).click();
    const credential = await enrolling;
    enrollPage.close();
    assert.ok(credential);

    // A real user hit this: `sandgate ask --input` with Face ID on failed
    // with "Approval arrived without the required biometric assertion",
    // because the input card sent the answer plain.
    const page = await loadPage(relayUrl, { hash: `#p=${pairing.pairId}&s=${pairing.secret}` });
    installAuthenticator(page.window, { ...device, credentialId });
    try {
      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
        biometric: credential!,
        requireBiometric: true,
      });
      const asking = approver.ask({ title: "SMS code?", timeoutSec: 20 });

      const sendBtn = await waitFor(() => page.window.document.querySelector(".card button.ok"));
      assert.match(sendBtn.textContent, /Face ID/, "the button must say what it will do");
      page.window.document.querySelector(".card .answer-input").value = "482913";
      sendBtn.click();

      assert.deepEqual(await asking, { answer: "482913", decision: "answered" });
      assert.deepEqual(page.alerts, [], `page alerted: ${page.alerts.join(" | ")}`);
    } finally {
      page.close();
    }
  });
});
