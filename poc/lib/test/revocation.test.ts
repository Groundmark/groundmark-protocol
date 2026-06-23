import { test } from "node:test";
import assert from "node:assert/strict";

import { MockHttpsFetcher } from "../src/attestation/fetcher.ts";
import { checkRevocation } from "../src/revocation/revocation.ts";
import type { AuditLogger, FailOpenAuditEntry, RevocationCheckInput } from "../src/revocation/revocation.ts";
import { VerificationError, type VerifyFailureReason } from "../src/errors.ts";

const IDSP = "idsp.groundmark-poc.example";
const REV = `https://${IDSP}/r/vr7Z_bv-gKX0q0cz3wFgug`;
const ENDPOINT = `https://${IDSP}/a/vr7Z_bv-gKX0q0cz3wFgug`;
const NOW = Math.floor(Date.parse("2026-06-10T00:00:00Z") / 1000);

function collector() {
  const entries: FailOpenAuditEntry[] = [];
  const logger: AuditLogger = { failOpen: (e) => entries.push(e) };
  return { entries, logger };
}

function input(over: Partial<RevocationCheckInput>): RevocationCheckInput {
  const { logger } = collector();
  return {
    fetcher: new MockHttpsFetcher(),
    revocationEndpoint: REV,
    endpointUrl: ENDPOINT,
    agentDomain: "agent.groundmark-poc.example",
    idsp: IDSP,
    claimType: "operator-verified",
    level: 1,
    issuedAtSeconds: Math.floor(Date.parse("2026-06-09T18:00:00Z") / 1000), // <24h before NOW
    now: NOW,
    policy: {},
    logger,
    transactionId: "txn-1",
    ...over,
  };
}

async function expectFail(p: Promise<unknown>, reason: VerifyFailureReason) {
  await assert.rejects(p, (e: unknown) => e instanceof VerificationError && e.reason === reason);
}

test("not revoked -> accepted, not failed open", async () => {
  const fetcher = new MockHttpsFetcher().setJson(REV, { revoked: false });
  const r = await checkRevocation(input({ fetcher }));
  assert.deepEqual(r, { failedOpen: false });
});

test("revoked -> claim_revoked", async () => {
  const fetcher = new MockHttpsFetcher().setJson(REV, { revoked: true });
  await expectFail(checkRevocation(input({ fetcher })), "claim_revoked");
});

test("L1 unreachable -> fail open with a redacted audit entry", async () => {
  const { entries, logger } = collector();
  const fetcher = new MockHttpsFetcher().setUnreachable(REV);
  const r = await checkRevocation(input({ fetcher, logger, level: 1 }));
  assert.equal(r.failedOpen, true);
  assert.equal(entries.length, 1);
  const e = entries[0]!;
  assert.equal(e.endpointOrigin, `https://${IDSP}`);
  assert.match(e.endpointUrlSha256, /^[0-9a-f]{64}$/);
  // The full bearer URL must never appear anywhere in the audit entry.
  assert.ok(!JSON.stringify(e).includes("vr7Z_bv-gKX0q0cz3wFgug"));
});

test("L3 unreachable -> fail closed", async () => {
  const fetcher = new MockHttpsFetcher().setUnreachable(REV);
  await expectFail(checkRevocation(input({ fetcher, level: 3 })), "revocation_unavailable_fail_closed");
});

test("L2 unreachable, no soft-fail policy -> fail closed", async () => {
  const fetcher = new MockHttpsFetcher().setUnreachable(REV);
  await expectFail(checkRevocation(input({ fetcher, level: 2, policy: {} })), "revocation_unavailable_fail_closed");
});

test("L2 unreachable, soft-fail allowed AND issued <24h ago -> fail open", async () => {
  const fetcher = new MockHttpsFetcher().setUnreachable(REV);
  const r = await checkRevocation(input({ fetcher, level: 2, policy: { allowLevel2SoftFail: true } }));
  assert.equal(r.failedOpen, true);
});

test("L2 unreachable, soft-fail allowed BUT issued >24h ago -> fail closed", async () => {
  const fetcher = new MockHttpsFetcher().setUnreachable(REV);
  const old = Math.floor(Date.parse("2026-06-01T00:00:00Z") / 1000);
  await expectFail(
    checkRevocation(input({ fetcher, level: 2, policy: { allowLevel2SoftFail: true }, issuedAtSeconds: old })),
    "revocation_unavailable_fail_closed",
  );
});

test("non-2xx revocation response is treated as unavailable", async () => {
  const fetcher = new MockHttpsFetcher().setJson(REV, { revoked: false }, { status: 503 });
  // L3 so unavailability surfaces as fail-closed rather than silent accept
  await expectFail(checkRevocation(input({ fetcher, level: 3 })), "revocation_unavailable_fail_closed");
});
