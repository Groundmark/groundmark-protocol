import { test } from "node:test";
import assert from "node:assert/strict";

import { MockDnssecResolver } from "../src/dns/mockResolver.ts";
import { resolveAgentKey, parseKeyId } from "../src/agent/keyResolver.ts";
import { VerificationError, type VerifyFailureReason } from "../src/errors.ts";
import { fixtureResolver } from "./helpers.ts";

const AGENT = "agent.groundmark-poc.example";
const AGENT_PUB = "nYBSoBzNUEcAT0oFKL-5LQgqTmdkQSLpxkAV1y1DGkg";

async function expectReason(p: Promise<unknown>, reason: VerifyFailureReason) {
  await assert.rejects(p, (e: unknown) => {
    assert.ok(e instanceof VerificationError, `expected VerificationError, got ${e}`);
    assert.equal(e.reason, reason);
    return true;
  });
}

test("resolves the fixture agent key (bare FQDN, single record)", async () => {
  const r = fixtureResolver();
  const key = await resolveAgentKey(r, parseKeyId(AGENT));
  assert.equal(key.alg, "ed25519");
  assert.equal(key.domain, AGENT);
  assert.equal(key.ttl, 300);
  const jwk = key.publicKey.export({ format: "jwk" }) as { x: string };
  assert.equal(jwk.x, AGENT_PUB);
  assert.deepEqual(r.queries, [`_agentid.${AGENT}`]);
});

test("non-secure DNSSEC status -> dnssec_validation_failed (unsigned zone)", async () => {
  const r = new MockDnssecResolver().setFailure(`_agentid.${AGENT}`, "insecure");
  await expectReason(resolveAgentKey(r, parseKeyId(AGENT)), "dnssec_validation_failed");
});

test("validated NODATA -> agentid_not_found", async () => {
  const r = new MockDnssecResolver(); // unknown name => secure with empty records
  await expectReason(resolveAgentKey(r, parseKeyId(AGENT)), "agentid_not_found");
});

test("multiple records, one missing kid -> agentid_missing_kid", async () => {
  const r = new MockDnssecResolver().setSecure(`_agentid.${AGENT}`, {
    records: [
      `v=gm1; k=ed25519; kid=k1; p=${AGENT_PUB}`,
      `v=gm1; k=ed25519; p=${AGENT_PUB}`,
    ],
  });
  await expectReason(resolveAgentKey(r, parseKeyId(`${AGENT}#k1`)), "agentid_missing_kid");
});

test("multiple records sharing a kid -> agentid_duplicate_kid", async () => {
  const r = new MockDnssecResolver().setSecure(`_agentid.${AGENT}`, {
    records: [
      `v=gm1; k=ed25519; kid=k1; p=${AGENT_PUB}`,
      `v=gm1; k=ed25519; kid=k1; p=${AGENT_PUB}`,
    ],
  });
  await expectReason(resolveAgentKey(r, parseKeyId(`${AGENT}#k1`)), "agentid_duplicate_kid");
});

test("bare-FQDN keyid with multiple records -> agentid_ambiguous", async () => {
  const r = new MockDnssecResolver().setSecure(`_agentid.${AGENT}`, {
    records: [
      `v=gm1; k=ed25519; kid=k1; p=${AGENT_PUB}`,
      `v=gm1; k=ed25519; kid=k2; p=${AGENT_PUB}`,
    ],
  });
  await expectReason(resolveAgentKey(r, parseKeyId(AGENT)), "agentid_ambiguous");
});

test("FQDN#kid selects the matching record; unknown kid -> keyid_no_match", async () => {
  const r = new MockDnssecResolver().setSecure(`_agentid.${AGENT}`, {
    records: [
      `v=gm1; k=ed25519; kid=k1; p=${AGENT_PUB}`,
      `v=gm1; k=ed25519; kid=k2; p=${AGENT_PUB}`,
    ],
  });
  const key = await resolveAgentKey(r, parseKeyId(`${AGENT}#k2`));
  assert.equal(key.kid, "k2");
  await expectReason(resolveAgentKey(r, parseKeyId(`${AGENT}#k9`)), "keyid_no_match");
});

test("unsupported key algorithm -> unsupported_key_alg", async () => {
  const r = new MockDnssecResolver().setSecure(`_agentid.${AGENT}`, {
    records: [`v=gm1; k=x-pqc-dilithium; p=${AGENT_PUB}`],
  });
  await expectReason(resolveAgentKey(r, parseKeyId(AGENT)), "unsupported_key_alg");
});

test("record not starting with v=gm1 -> agentid_malformed", async () => {
  const r = new MockDnssecResolver().setSecure(`_agentid.${AGENT}`, {
    records: [`k=ed25519; p=${AGENT_PUB}`],
  });
  await expectReason(resolveAgentKey(r, parseKeyId(AGENT)), "agentid_malformed");
});
