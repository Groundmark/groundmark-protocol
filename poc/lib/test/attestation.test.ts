import { test } from "node:test";
import assert from "node:assert/strict";

import { parseAttestation } from "../src/attestation/payload.ts";
import { verifyAttestation } from "../src/attestation/verify.ts";
import type { AttestationVerifyContext } from "../src/attestation/verify.ts";
import { VerificationError, type VerifyFailureReason } from "../src/errors.ts";
import { fixtureResolver, readPoc } from "./helpers.ts";

const AGENT = "agent.groundmark-poc.example";
const IDSP = "idsp.groundmark-poc.example";
const OV_REF = `https://${IDSP}/a/vr7Z_bv-gKX0q0cz3wFgug`;
const CP_REF = `https://${IDSP}/a/zSACSyRu73820aiZECpTkw`;
const NOW = Math.floor(Date.parse("2026-06-10T00:00:00Z") / 1000);

function ctx(over: Partial<AttestationVerifyContext> = {}): AttestationVerifyContext {
  return {
    agentDomain: AGENT,
    refUrl: OV_REF,
    now: NOW,
    levelFloor: 1,
    resolver: fixtureResolver(),
    ...over,
  };
}

function good(name: string) {
  return parseAttestation(readPoc("fixtures", "good", name + ".json"));
}
function adversarial(name: string) {
  return parseAttestation(readPoc("fixtures", "adversarial", name + ".json"));
}

async function expectFail(p: Promise<unknown>, reason: VerifyFailureReason) {
  await assert.rejects(p, (e: unknown) => {
    assert.ok(e instanceof VerificationError, `expected VerificationError, got ${e}`);
    assert.equal(e.reason, reason, `expected ${reason}, got ${e.reason}`);
    return true;
  });
}

test("good operator-verified attestation verifies (JCS + Ed25519 cross-impl)", async () => {
  const payload = await verifyAttestation(good("operator-verified"), ctx());
  assert.equal(payload.claim_type, "operator-verified");
  assert.equal(payload.level, 1);
  assert.equal(payload.subject, AGENT);
  assert.equal(payload.idsp, IDSP);
  assert.deepEqual(payload.method_disclosure.methods, [
    "corporate-registry-lookup",
    "organizational-domain-email-confirmation",
  ]);
});

test("good x-registry-example-canadian-presence (custom claim) verifies", async () => {
  const payload = await verifyAttestation(
    good("x-registry-example-canadian-presence"),
    ctx({ refUrl: CP_REF }),
  );
  assert.equal(payload.claim_type, "x-registry-example-canadian-presence");
  assert.deepEqual(payload.claim_value, { present: true, jurisdiction: "CA" });
});

// Each adversarial case must fail on its ONE intended check.

test("expired -> attestation_expired", async () => {
  await expectFail(verifyAttestation(adversarial("expired"), ctx()), "attestation_expired");
});

test("wrong-subject -> wrong_subject", async () => {
  await expectFail(verifyAttestation(adversarial("wrong-subject"), ctx()), "wrong_subject");
});

test("bad-signature -> attestation_signature_invalid", async () => {
  await expectFail(verifyAttestation(adversarial("bad-signature"), ctx()), "attestation_signature_invalid");
});

test("endpoint-mismatch -> endpoint_mismatch (served from the good ref)", async () => {
  // Per fixtures/README: treat endpoint-mismatch as served from the good ref URL.
  await expectFail(verifyAttestation(adversarial("endpoint-mismatch"), ctx()), "endpoint_mismatch");
});

test("unknown-schema-version -> unknown_schema_version", async () => {
  await expectFail(verifyAttestation(adversarial("unknown-schema-version"), ctx()), "unknown_schema_version");
});

test("below-policy-level -> below_policy_level (floor = 1)", async () => {
  await expectFail(verifyAttestation(adversarial("below-policy-level"), ctx()), "below_policy_level");
});

test("IDSP zone not DNSSEC-secure -> idsp_dnssec_validation_failed", async () => {
  const resolver = fixtureResolver().setFailure(`_agentid.${IDSP}`, "insecure");
  await expectFail(verifyAttestation(good("operator-verified"), ctx({ resolver })), "idsp_dnssec_validation_failed");
});

test("signing_key_id with no matching IDSP record -> signing_key_id_no_match", async () => {
  // Re-publish the IDSP key under a different kid than the attestation references (k1).
  const resolver = fixtureResolver().setSecure(`_agentid.${IDSP}`, {
    records: ["v=gm1; k=ed25519; kid=k9; p=JtwMfz3wkEZ5KjJJmO0W9SVkdtlNfnPjqz5lfDDczlc"],
  });
  await expectFail(verifyAttestation(good("operator-verified"), ctx({ resolver })), "signing_key_id_no_match");
});
