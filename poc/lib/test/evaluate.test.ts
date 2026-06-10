import { test } from "node:test";
import assert from "node:assert/strict";

import { evaluateAttestations } from "../src/attestation/evaluate.ts";
import type { EvaluateOptions } from "../src/attestation/evaluate.ts";
import { verifyAgentRequest } from "../src/verify.ts";
import { MockHttpsFetcher } from "../src/attestation/fetcher.ts";
import { MockDnssecResolver } from "../src/dns/mockResolver.ts";
import type { AuditLogger, FailOpenAuditEntry } from "../src/revocation/revocation.ts";
import { fixtureResolver, fixtureFetcher, readPoc } from "./helpers.ts";

const AGENT = "agent.groundmark-poc.example";
const IDSP = "idsp.groundmark-poc.example";
const OV_REF = `https://${IDSP}/a/vr7Z_bv-gKX0q0cz3wFgug`;
const OV_REV = `https://${IDSP}/r/vr7Z_bv-gKX0q0cz3wFgug`;
const NOW = Math.floor(Date.parse("2026-06-10T00:00:00Z") / 1000);
const FIXTURE_NOW = 1747654321; // request vector signing time

function noopLogger(): { entries: FailOpenAuditEntry[]; logger: AuditLogger } {
  const entries: FailOpenAuditEntry[] = [];
  return { entries, logger: { failOpen: (e) => entries.push(e) } };
}

function evalOpts(over: Partial<EvaluateOptions> = {}): EvaluateOptions {
  return {
    resolver: fixtureResolver(),
    fetcher: fixtureFetcher(),
    now: NOW,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified", "x-registry-example-canadian-presence"] },
    logger: noopLogger().logger,
    transactionId: "txn-e2e",
    ...over,
  };
}

test("headline good case: both stacked claims verify, policy satisfied, methods surfaced", async () => {
  const v = await evaluateAttestations(AGENT, evalOpts());
  assert.equal(v.policySatisfied, true);
  assert.deepEqual(v.missingClaims, []);
  assert.equal(v.claims.length, 2);
  const ov = v.claims.find((c) => c.claimType === "operator-verified")!;
  assert.equal(ov.ok, true);
  assert.equal(ov.level, 1);
  assert.equal(ov.idsp, IDSP);
  assert.equal(ov.failedOpen, false);
  // method_disclosure is surfaced, not collapsed (instruction C9)
  assert.deepEqual(ov.methodDisclosure?.methods, [
    "corporate-registry-lookup",
    "organizational-domain-email-confirmation",
  ]);
});

test("revoked claim -> claim rejected with claim_revoked, policy not satisfied", async () => {
  const fetcher = new MockHttpsFetcher()
    .setRaw(OV_REF, readPoc("fixtures", "adversarial", "revoked.json"), { contentType: "application/json" })
    .setJson(OV_REV, { revoked: true });
  const v = await evaluateAttestations(AGENT, evalOpts({
    fetcher,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
  }));
  const ov = v.claims.find((c) => c.claimType === "operator-verified")!;
  assert.equal(ov.ok, false);
  assert.equal(ov.reason, "claim_revoked");
  assert.equal(v.policySatisfied, false);
  assert.deepEqual(v.missingClaims, ["operator-verified"]);
});

test("attestation endpoint unreachable -> attestation_fetch_failed", async () => {
  const fetcher = new MockHttpsFetcher().setUnreachable(OV_REF);
  const v = await evaluateAttestations(AGENT, evalOpts({
    fetcher,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
  }));
  const ov = v.claims.find((c) => c.claimType === "operator-verified")!;
  assert.equal(ov.ok, false);
  assert.equal(ov.reason, "attestation_fetch_failed");
});

test("self-asserted val-form claim is reported as Level 0, unverified", async () => {
  const resolver = new MockDnssecResolver().setSecure(`_agentclaim.${AGENT}`, {
    records: ["v=gm1; claim=operator-contact; val=ops@acmecorp.example"],
  });
  const v = await evaluateAttestations(AGENT, evalOpts({
    resolver,
    policy: { levelFloor: 0 },
  }));
  assert.equal(v.claims.length, 1);
  const c = v.claims[0]!;
  assert.equal(c.selfAsserted, true);
  assert.equal(c.level, 0);
  assert.equal(c.ok, true);
});

test("expired exp= DNS hint -> claim_exp_passed without fetching", async () => {
  const resolver = new MockDnssecResolver().setSecure(`_agentclaim.${AGENT}`, {
    records: [`v=gm1; claim=operator-verified; idsp=${IDSP}; ref=${OV_REF}; exp=2026-01-01`],
  });
  // fetcher that would throw if consulted, proving exp is enforced pre-fetch
  const fetcher = new MockHttpsFetcher();
  const v = await evaluateAttestations(AGENT, evalOpts({
    resolver,
    fetcher,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
  }));
  assert.equal(v.claims[0]!.reason, "claim_exp_passed");
});

test("top-level verifyAgentRequest: Level 0 only (no attestation policy) passes", async () => {
  const raw = readPoc("fixtures", "request", "signed-request.http");
  const v = await verifyAgentRequest(raw, { resolver: fixtureResolver(), now: FIXTURE_NOW });
  assert.equal(v.ok, true);
  assert.equal(v.request.ok, true);
  assert.equal(v.attestations, undefined);
});

test("top-level verifyAgentRequest: request + attestation policy end to end", async () => {
  const raw = readPoc("fixtures", "request", "signed-request.http");
  const { logger } = noopLogger();
  const v = await verifyAgentRequest(raw, {
    resolver: fixtureResolver(),
    fetcher: fixtureFetcher(),
    now: FIXTURE_NOW,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
    logger,
    transactionId: "txn-combined",
  });
  assert.equal(v.request.ok, true);
  assert.equal(v.attestations?.policySatisfied, true);
  assert.equal(v.ok, true);
});

test("top-level verifyAgentRequest: bad request short-circuits before attestations", async () => {
  const raw = readPoc("fixtures", "request", "signed-request.http");
  const { logger } = noopLogger();
  const v = await verifyAgentRequest(raw, {
    resolver: fixtureResolver(),
    fetcher: fixtureFetcher(),
    now: FIXTURE_NOW + 10_000, // stale -> request fails
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
    logger,
  });
  assert.equal(v.ok, false);
  assert.equal(v.request.ok, false);
  assert.equal(v.attestations, undefined);
});
