import { test } from "node:test";
import assert from "node:assert/strict";

import { verifyRequestMessage } from "../src/verifyRequest.ts";
import { IssuedNonceStore } from "../src/nonce/issuedNonceStore.ts";
import { signRequest, resolverForKey } from "./helpers.ts";

const AGENT = "agent.groundmark-poc.example";

test("an issued nonce is accepted once; a second use is refused", async () => {
  const store = new IssuedNonceStore({ now: () => 1000 });
  const { nonce, expiresAt } = store.issue();
  assert.equal(expiresAt, 1300);
  assert.match(nonce, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(await store.consumeOnce(nonce, expiresAt), true);
  assert.equal(await store.consumeOnce(nonce, expiresAt), false);
  assert.equal(store.size, 0);
});

test("a nonce this relying party never issued is refused", async () => {
  const store = new IssuedNonceStore({ now: () => 1000 });
  store.issue();
  assert.equal(await store.consumeOnce("made-up-by-the-agent", 1300), false);
});

test("an issued nonce is refused once its lifetime has passed, and swept", async () => {
  let t = 1000;
  const store = new IssuedNonceStore({ now: () => t, lifetimeSeconds: 60 });
  const { nonce } = store.issue();
  t = 1060;
  assert.equal(await store.consumeOnce(nonce, 9999), false);   // the request's own expiry doesn't extend it
  store.issue();
  t = 2000;
  store.sweep();
  assert.equal(store.size, 0);
});

test("the lifetime can't exceed 300 seconds (core §5.5.2)", () => {
  assert.throws(() => new IssuedNonceStore({ lifetimeSeconds: 301 }), RangeError);
  assert.throws(() => new IssuedNonceStore({ lifetimeSeconds: 0 }), RangeError);
});

test("concurrent uses of one issued nonce: exactly one wins", async () => {
  const store = new IssuedNonceStore({ now: () => 1000 });
  const { nonce, expiresAt } = store.issue();
  const results = await Promise.all(Array.from({ length: 5 }, () => store.consumeOnce(nonce, expiresAt)));
  assert.equal(results.filter(Boolean).length, 1);
});

test("verifyRequest: a validly signed request with a nonce we didn't issue is refused", async () => {
  const now = 7000;
  const store = new IssuedNonceStore({ now: () => now, random: () => "issued-by-rp" });
  const opts = { now, requireNonce: true, nonceStore: store } as const;

  const madeUp = signRequest({ agentDomain: AGENT, created: now, nonce: "chosen-by-agent" });
  const v1 = await verifyRequestMessage(madeUp.message, resolverForKey(AGENT, madeUp.publicKeyB64url), opts);
  assert.equal(v1.ok, false);
  if (v1.ok === false) {
    assert.equal(v1.reason, "nonce_replayed");
    assert.match(v1.message, /not issued by this relying party/);
  }

  const { nonce } = store.issue();
  const good = signRequest({ agentDomain: AGENT, created: now, nonce });
  const v2 = await verifyRequestMessage(good.message, resolverForKey(AGENT, good.publicKeyB64url), opts);
  assert.equal(v2.ok, true, JSON.stringify(v2));
});
