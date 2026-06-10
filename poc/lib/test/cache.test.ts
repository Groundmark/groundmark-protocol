import { test } from "node:test";
import assert from "node:assert/strict";

import { computeCacheTtl, TtlCache } from "../src/cache/ttl.ts";

test("computeCacheTtl is the lesser of DNS TTL, max-age, and time-to-expiry", () => {
  const now = 1000;
  assert.equal(computeCacheTtl({ now, dnsTtl: 300, maxAge: 600, expiresAtSeconds: now + 999999 }), 300);
  assert.equal(computeCacheTtl({ now, dnsTtl: 300, maxAge: 120, expiresAtSeconds: now + 999999 }), 120);
  assert.equal(computeCacheTtl({ now, dnsTtl: 300, maxAge: 600, expiresAtSeconds: now + 60 }), 60);
});

test("computeCacheTtl never returns negative (already-expired)", () => {
  assert.equal(computeCacheTtl({ now: 1000, expiresAtSeconds: 900 }), 0);
});

test("computeCacheTtl with no bounds is 0", () => {
  assert.equal(computeCacheTtl({ now: 1000 }), 0);
});

test("TtlCache respects expiry against the injected clock", () => {
  const c = new TtlCache<string>();
  c.set("k", "v", 100, 1000);
  assert.equal(c.get("k", 1050), "v");
  assert.equal(c.get("k", 1100), undefined); // expired exactly at ceiling
  assert.equal(c.size, 0);
});

test("TtlCache treats non-positive TTL as do-not-cache", () => {
  const c = new TtlCache<string>();
  c.set("k", "v", 0, 1000);
  assert.equal(c.get("k", 1000), undefined);
  assert.equal(c.size, 0);
});
