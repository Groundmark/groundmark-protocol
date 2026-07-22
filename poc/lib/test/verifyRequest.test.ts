import { test } from "node:test";
import assert from "node:assert/strict";

import { verifyRequest, verifyRequestMessage } from "../src/verifyRequest.ts";
import type { NonceStore, RequestVerdict } from "../src/verifyRequest.ts";
import type { VerifyFailureReason } from "../src/errors.ts";
import {
  readPoc,
  fixtureResolver,
  signRequest,
  resolverForKey,
} from "./helpers.ts";

const AGENT = "agent.groundmark-poc.example";
// The committed RFC 9421 vector was signed at this instant (created=...).
const FIXTURE_NOW = 1747654321;

function assertFail(v: RequestVerdict, reason: VerifyFailureReason) {
  assert.equal(v.ok, false, `expected failure ${reason}, got ${JSON.stringify(v)}`);
  if (v.ok === false) assert.equal(v.reason, reason);
}

class MemoryNonceStore implements NonceStore {
  readonly consumed = new Map<string, number>();

  async consumeOnce(nonce: string, expiresAt: number): Promise<boolean> {
    if (this.consumed.has(nonce)) return false;
    this.consumed.set(nonce, expiresAt);
    return true;
  }
}

test("the committed RFC 9421 request vector verifies end to end", async () => {
  const raw = readPoc("fixtures", "request", "signed-request.http");
  const v = await verifyRequest(raw, fixtureResolver(), { now: FIXTURE_NOW });
  assert.equal(v.ok, true, JSON.stringify(v));
  if (v.ok) {
    assert.equal(v.agentDomain, AGENT);
    assert.equal(v.keyid, AGENT);
    assert.equal(v.created, FIXTURE_NOW);
    assert.equal(v.expires, FIXTURE_NOW + 300);
    assert.equal(v.ttl, 300);
  }
});

test("freshness: created beyond +/-300s -> created_out_of_window", async () => {
  const raw = readPoc("fixtures", "request", "signed-request.http");
  const v = await verifyRequest(raw, fixtureResolver(), { now: FIXTURE_NOW + 301 });
  assertFail(v, "created_out_of_window");
});

test("tampered signature byte -> signature_invalid", async () => {
  const { message, publicKeyB64url } = signRequest({ agentDomain: AGENT, created: 1000 });
  // flip a byte of the base64'd signature value
  const sigHeader = message.headers.get("signature")![0]!;
  const inner = sigHeader.slice("gm=:".length, -1);
  const bytes = Buffer.from(inner, "base64");
  bytes[0] = bytes[0]! ^ 0x01;
  message.headers.set("signature", [`gm=:${bytes.toString("base64")}:`]);
  const v = await verifyRequestMessage(message, resolverForKey(AGENT, publicKeyB64url), { now: 1000 });
  assertFail(v, "signature_invalid");
});

test("a freshly signed request verifies (round-trip)", async () => {
  const { message, publicKeyB64url } = signRequest({
    agentDomain: AGENT,
    created: 2000,
    expires: 2200,
    body: Buffer.from('{"sku":"X-42","quantity":3}'),
  });
  const v = await verifyRequestMessage(message, resolverForKey(AGENT, publicKeyB64url), { now: 2050 });
  assert.equal(v.ok, true, JSON.stringify(v));
});

test("expires in the past -> expires_in_past", async () => {
  const { message, publicKeyB64url } = signRequest({ agentDomain: AGENT, created: 3000, expires: 3100 });
  const v = await verifyRequestMessage(message, resolverForKey(AGENT, publicKeyB64url), { now: 3150 });
  assertFail(v, "expires_in_past");
});

test("body tampered after signing -> content_digest_mismatch", async () => {
  const { message, publicKeyB64url } = signRequest({
    agentDomain: AGENT,
    created: 4000,
    body: Buffer.from('{"sku":"X-42","quantity":3}'),
  });
  message.body = Buffer.from('{"sku":"X-42","quantity":9001}'); // digest no longer matches
  const v = await verifyRequestMessage(message, resolverForKey(AGENT, publicKeyB64url), { now: 4000 });
  assertFail(v, "content_digest_mismatch");
});

test("@authority binding: changing Host invalidates the signature", async () => {
  const { message, publicKeyB64url } = signRequest({ agentDomain: AGENT, created: 5000 });
  message.headers.set("host", ["api.attacker.example"]);
  message.authority = "api.attacker.example";
  message.url = "https://api.attacker.example/orders";
  const v = await verifyRequestMessage(message, resolverForKey(AGENT, publicKeyB64url), { now: 5000 });
  assertFail(v, "signature_invalid");
});

test("missing Signature-Input -> sig_input_missing", async () => {
  const { message, publicKeyB64url } = signRequest({ agentDomain: AGENT, created: 6000 });
  message.headers.delete("signature-input");
  const v = await verifyRequestMessage(message, resolverForKey(AGENT, publicKeyB64url), { now: 6000 });
  assertFail(v, "sig_input_missing");
});

test("nonce replay: second use of a nonce -> nonce_replayed", async () => {
  const store = new MemoryNonceStore();
  const opts = { now: 7000, requireNonce: true, nonceStore: store } as const;

  const first = signRequest({ agentDomain: AGENT, created: 7000, nonce: "abc123" });
  const r1 = resolverForKey(AGENT, first.publicKeyB64url);
  const v1 = await verifyRequestMessage(first.message, r1, opts);
  assert.equal(v1.ok, true, JSON.stringify(v1));

  const second = signRequest({ agentDomain: AGENT, created: 7000, nonce: "abc123" });
  const r2 = resolverForKey(AGENT, second.publicKeyB64url);
  const v2 = await verifyRequestMessage(second.message, r2, opts);
  assertFail(v2, "nonce_replayed");
});

test("Level 0 nonce commit is atomic under concurrent identical requests", async () => {
  const store = new MemoryNonceStore();
  const signed = signRequest({
    agentDomain: AGENT,
    created: 10_000,
    expires: 10_300,
    nonce: "level0-concurrent",
  });
  const resolver = resolverForKey(AGENT, signed.publicKeyB64url);

  const results = await Promise.all([
    verifyRequestMessage(signed.message, resolver, { now: 10_000, requireNonce: true, nonceStore: store }),
    verifyRequestMessage(signed.message, resolver, { now: 10_000, requireNonce: true, nonceStore: store }),
  ]);

  assert.equal(results.filter((v) => v.ok).length, 1, JSON.stringify(results));
  const replay = results.find((v) => !v.ok);
  assert.ok(replay);
  assertFail(replay, "nonce_replayed");
  assert.equal(store.consumed.get("level0-concurrent"), 10_300);
});

test("requireNonce but no nonce present -> nonce_missing", async () => {
  const store = new MemoryNonceStore();
  const { message, publicKeyB64url } = signRequest({ agentDomain: AGENT, created: 8000 });
  const v = await verifyRequestMessage(message, resolverForKey(AGENT, publicKeyB64url), {
    now: 8000,
    requireNonce: true,
    nonceStore: store,
  });
  assertFail(v, "nonce_missing");
});

test("DNSSEC failure at agent lookup -> dnssec_validation_failed", async () => {
  const raw = readPoc("fixtures", "request", "signed-request.http");
  const r = fixtureResolver().setFailure(`_agentid.${AGENT}`, "bogus");
  const v = await verifyRequest(raw, r, { now: FIXTURE_NOW });
  assertFail(v, "dnssec_validation_failed");
});

test("a failed request does not consume its nonce; a later valid request may reuse it", async () => {
  const store = new MemoryNonceStore();
  const NONCE = "shared-nonce-9000";

  // 1) Invalid request (tampered signature) carrying NONCE -> signature_invalid.
  const bad = signRequest({ agentDomain: AGENT, created: 9000, nonce: NONCE });
  const badSig = bad.message.headers.get("signature")![0]!;
  const bytes = Buffer.from(badSig.slice("gm=:".length, -1), "base64");
  bytes[0] = bytes[0]! ^ 0x01;
  bad.message.headers.set("signature", [`gm=:${bytes.toString("base64")}:`]);
  const v1 = await verifyRequestMessage(bad.message, resolverForKey(AGENT, bad.publicKeyB64url), {
    now: 9000,
    requireNonce: true,
    nonceStore: store,
  });
  assertFail(v1, "signature_invalid");
  assert.equal(store.consumed.has(NONCE), false, "a failed request must NOT consume its nonce");

  // 2) A fresh, valid request reusing the same nonce must still succeed.
  const good = signRequest({ agentDomain: AGENT, created: 9000, nonce: NONCE });
  const v2 = await verifyRequestMessage(good.message, resolverForKey(AGENT, good.publicKeyB64url), {
    now: 9000,
    requireNonce: true,
    nonceStore: store,
  });
  assert.equal(v2.ok, true, JSON.stringify(v2));
  assert.equal(store.consumed.has(NONCE), true, "a fully-verified request consumes its nonce");
});
