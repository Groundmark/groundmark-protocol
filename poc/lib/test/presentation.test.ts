import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";

import { verifyAgentRequest } from "../src/verify.ts";
import type { VerifyAgentRequestOptions, GroundmarkVerdict } from "../src/verify.ts";
import type { NonceStore } from "../src/verifyRequest.ts";
import type { AuditLogger, FailOpenAuditEntry } from "../src/revocation/revocation.ts";
import type { VerifyFailureReason } from "../src/errors.ts";
import { jcsBytes } from "../src/attestation/canonical.ts";
import { MockHttpsFetcher } from "../src/attestation/fetcher.ts";
import { fixtureResolver, fixtureFetcher, readPoc } from "./helpers.ts";

const AGENT = "agent.groundmark-poc.example";
const IDSP = "idsp.groundmark-poc.example";
const OV_REF = `https://${IDSP}/a/vr7Z_bv-gKX0q0cz3wFgug`;
// The composite presentation vector was signed at this instant (created=...).
const PRES_NOW = 1747654321;

class MemoryNonceStore implements NonceStore {
  readonly consumed = new Map<string, number>();

  async consumeOnce(nonce: string, expiresAt: number): Promise<boolean> {
    if (this.consumed.has(nonce)) return false;
    this.consumed.set(nonce, expiresAt);
    return true;
  }
}

function newNonceStore(): MemoryNonceStore {
  return new MemoryNonceStore();
}

function noopLogger(): AuditLogger {
  return { failOpen: (_e: FailOpenAuditEntry) => void 0 };
}

/** Standard presentation-profile verification options (one fresh nonce store each). */
function presentationOpts(over: Partial<VerifyAgentRequestOptions> = {}): VerifyAgentRequestOptions {
  return {
    resolver: fixtureResolver(),
    fetcher: fixtureFetcher(),
    now: PRES_NOW,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
    logger: noopLogger(),
    transactionId: "txn-presentation",
    requireGroundmarkClaim: true,
    requireNonce: true,
    nonceStore: newNonceStore(),
    ...over,
  };
}

function readPres(name: string): Buffer {
  return readPoc("fixtures", "presentation", name);
}

function publicKeyB64url(publicKey: KeyObject): string {
  return (publicKey.export({ format: "jwk" }) as { x: string }).x;
}

function signedAttestation(
  privateKey: KeyObject,
  spec: {
    claimType: string;
    idsp: string;
    ref: string;
    revocationEndpoint: string;
  },
): Buffer {
  const payload = {
    schema_version: "1.0",
    subject: AGENT,
    claim_type: spec.claimType,
    claim_value: { verified: true },
    level: 1,
    idsp: spec.idsp,
    issued_at: "2026-05-19T12:00:00Z",
    expires_at: "2026-12-01T00:00:00Z",
    method_disclosure: { methods: ["unit-test-method"] },
    endpoint_url: spec.ref,
    revocation_endpoint: spec.revocationEndpoint,
    signing_key_id: "k-test",
  };
  const signature = cryptoSign(null, jcsBytes(payload), privateKey).toString("base64url");
  return Buffer.from(JSON.stringify({ ...payload, signature }, null, 2) + "\n", "utf8");
}

function signedPresentationRequest(spec: {
  claimType: string;
  ref: string;
  nonce: string;
  created?: number;
  expires?: number;
}): { raw: Buffer; publicKeyB64url: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const created = spec.created ?? PRES_NOW;
  const expires = spec.expires ?? created + 300;
  const authority = "api.relying-party.example";
  const targetUri = `https://${authority}/present`;
  const body = Buffer.from('{"action":"present-credential"}');
  const digest = createHash("sha256").update(body).digest().toString("base64");
  const contentDigest = `sha-256=:${digest}:`;
  const claimValue = `claim-type="${spec.claimType}"; ref="${spec.ref}"`;
  const sigParams =
    `("@method" "@authority" "@target-uri" "content-digest" "groundmark-claim")` +
    `;created=${created};expires=${expires};nonce="${spec.nonce}";keyid="${AGENT}";alg="ed25519"`;
  const signatureBase = [
    '"@method": POST',
    `"@authority": ${authority}`,
    `"@target-uri": ${targetUri}`,
    `"content-digest": ${contentDigest}`,
    `"groundmark-claim": ${claimValue}`,
    `"@signature-params": ${sigParams}`,
  ].join("\n");
  const signature = cryptoSign(null, Buffer.from(signatureBase, "utf8"), privateKey).toString("base64");
  const raw = Buffer.concat([
    Buffer.from(
      [
        "POST /present HTTP/1.1",
        `Host: ${authority}`,
        "Content-Type: application/json",
        `Content-Digest: ${contentDigest}`,
        `Groundmark-Claim: ${claimValue}`,
        `Signature-Input: gm=${sigParams}`,
        `Signature: gm=:${signature}:`,
        "",
        "",
      ].join("\r\n"),
      "latin1",
    ),
    body,
  ]);
  return { raw, publicKeyB64url: publicKeyB64url(publicKey) };
}

function presentationWorld(spec: {
  dnsClaimType: string;
  payloadClaimType: string;
  dnsIdsp: string;
  payloadIdsp: string;
  ref: string;
  nonce: string;
}) {
  const revocationEndpoint = `${spec.ref.replace("/a/", "/r/")}-status`;
  const agent = signedPresentationRequest({
    claimType: spec.dnsClaimType,
    ref: spec.ref,
    nonce: spec.nonce,
  });
  const { publicKey: idspPublic, privateKey: idspPrivate } = generateKeyPairSync("ed25519");
  const resolver = fixtureResolver()
    .setSecure(`_agentid.${AGENT}`, {
      records: [`v=gm1; k=ed25519; p=${agent.publicKeyB64url}`],
    })
    .setSecure(`_agentclaim.${AGENT}`, {
      records: [
        `v=gm1; claim=${spec.dnsClaimType}; idsp=${spec.dnsIdsp}; ref=${spec.ref}; exp=2026-12-01`,
      ],
    })
    .setSecure(`_agentid.${spec.payloadIdsp}`, {
      records: [`v=gm1; k=ed25519; kid=k-test; p=${publicKeyB64url(idspPublic)}`],
    });
  const fetcher = new MockHttpsFetcher()
    .setRaw(
      spec.ref,
      signedAttestation(idspPrivate, {
        claimType: spec.payloadClaimType,
        idsp: spec.payloadIdsp,
        ref: spec.ref,
        revocationEndpoint,
      }),
      { contentType: "application/json" },
    )
    .setJson(revocationEndpoint, { revoked: false });
  return { raw: agent.raw, resolver, fetcher };
}

/** Assert the request layer rejected with a specific reason. */
function assertRequestFail(v: GroundmarkVerdict, reason: VerifyFailureReason) {
  assert.equal(v.ok, false, `expected request failure ${reason}, got ${JSON.stringify(v)}`);
  assert.equal(v.request.ok, false);
  if (v.request.ok === false) assert.equal(v.request.reason, reason);
}

test("good composite presentation: request verifies, claim bound, policy satisfied", async () => {
  const v = await verifyAgentRequest(readPres("presentation.http"), presentationOpts());
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.request.ok, true);
  if (v.request.ok) {
    // the signature-covered Groundmark-Claim was parsed and surfaced
    assert.deepEqual(v.request.groundmarkClaim, { claimType: "operator-verified", ref: OV_REF });
  }
  assert.equal(v.attestations?.policySatisfied, true);
  assert.equal(v.attestations?.binding?.ok, true);
  assert.equal(v.attestations?.binding?.claimType, "operator-verified");
});

test("matching DNS claim, IDSP, and endpoint bindings remain accepted", async () => {
  const store = newNonceStore();
  const world = presentationWorld({
    dnsClaimType: "operator-verified",
    payloadClaimType: "operator-verified",
    dnsIdsp: "idsp-match.groundmark-poc.example",
    payloadIdsp: "idsp-match.groundmark-poc.example",
    ref: "https://idsp-match.groundmark-poc.example/a/matching-binding",
    nonce: "matching-binding-nonce",
  });
  const v = await verifyAgentRequest(world.raw, presentationOpts({
    resolver: world.resolver,
    fetcher: world.fetcher,
    nonceStore: store,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
  }));

  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.attestations?.binding?.ok, true);
  const claim = v.attestations?.claims.find((c) => c.claimType === "operator-verified");
  assert.equal(claim?.ok, true);
  assert.equal(claim?.idsp, "idsp-match.groundmark-poc.example");
  assert.equal(store.consumed.has("matching-binding-nonce"), true);
});

test("adversarial: DNS claim differs from signed payload claim_type -> attestation_claim_type_mismatch", async () => {
  const store = newNonceStore();
  const ref = "https://idsp-bind.groundmark-poc.example/a/claim-binding";
  const failed = presentationWorld({
    dnsClaimType: "jurisdiction-licensed",
    payloadClaimType: "operator-verified",
    dnsIdsp: "idsp-bind.groundmark-poc.example",
    payloadIdsp: "idsp-bind.groundmark-poc.example",
    ref,
    nonce: "claim-binding-nonce",
  });
  const v = await verifyAgentRequest(failed.raw, presentationOpts({
    resolver: failed.resolver,
    fetcher: failed.fetcher,
    nonceStore: store,
    policy: { levelFloor: 1, requiredClaimTypes: ["jurisdiction-licensed"] },
  }));

  assert.equal(v.request.ok, true);
  assert.equal(v.ok, false);
  const claim = v.attestations?.claims.find((c) => c.claimType === "jurisdiction-licensed");
  assert.equal(claim?.ok, false);
  assert.equal(claim?.reason, "attestation_claim_type_mismatch");
  assert.deepEqual(v.attestations?.missingClaims, ["jurisdiction-licensed"]);
  assert.equal(v.attestations?.binding?.reason, "attestation_claim_type_mismatch");
  assert.notEqual(v.attestations?.binding?.reason, "groundmark_claim_ref_mismatch");
  assert.equal(store.consumed.has("claim-binding-nonce"), false, "binding failure must not consume nonce");

  const corrected = presentationWorld({
    dnsClaimType: "jurisdiction-licensed",
    payloadClaimType: "jurisdiction-licensed",
    dnsIdsp: "idsp-bind.groundmark-poc.example",
    payloadIdsp: "idsp-bind.groundmark-poc.example",
    ref,
    nonce: "claim-binding-nonce",
  });
  const retry = await verifyAgentRequest(corrected.raw, presentationOpts({
    resolver: corrected.resolver,
    fetcher: corrected.fetcher,
    nonceStore: store,
    policy: { levelFloor: 1, requiredClaimTypes: ["jurisdiction-licensed"] },
  }));
  assert.equal(retry.ok, true, JSON.stringify(retry));
  assert.equal(store.consumed.has("claim-binding-nonce"), true);
});

test("adversarial: DNS IDSP differs from signed payload idsp -> attestation_idsp_mismatch", async () => {
  const store = newNonceStore();
  const world = presentationWorld({
    dnsClaimType: "operator-verified",
    payloadClaimType: "operator-verified",
    dnsIdsp: "idsp-a.groundmark-poc.example",
    payloadIdsp: "idsp-b.groundmark-poc.example",
    ref: "https://idsp-a.groundmark-poc.example/a/idsp-binding",
    nonce: "idsp-binding-nonce",
  });
  const v = await verifyAgentRequest(world.raw, presentationOpts({
    resolver: world.resolver,
    fetcher: world.fetcher,
    nonceStore: store,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
  }));

  assert.equal(v.request.ok, true);
  assert.equal(v.ok, false);
  const claim = v.attestations?.claims.find((c) => c.claimType === "operator-verified");
  assert.equal(claim?.ok, false);
  assert.equal(claim?.reason, "attestation_idsp_mismatch");
  assert.deepEqual(v.attestations?.missingClaims, ["operator-verified"]);
  assert.equal(v.attestations?.binding?.reason, "attestation_idsp_mismatch");
  assert.notEqual(v.attestations?.binding?.reason, "groundmark_claim_ref_mismatch");
  assert.equal(store.consumed.has("idsp-binding-nonce"), false, "IDSP binding failure must not consume nonce");
});

test("config: requireGroundmarkClaim without a fetcher/logger throws at setup (no silent half-check)", async () => {
  // A policy that evaluates attestations, but the fetcher + logger needed to run
  // the DNS/attestation half of the binding are missing -> must throw, not return
  // a verdict reflecting only the request-layer half.
  await assert.rejects(
    () =>
      verifyAgentRequest(readPres("presentation.http"), {
        resolver: fixtureResolver(),
        now: PRES_NOW,
        policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
        requireGroundmarkClaim: true,
        // no fetcher, no logger
      }),
    /requireGroundmarkClaim/,
  );
});

test("config: requireGroundmarkClaim without an evaluating policy throws at setup", async () => {
  await assert.rejects(
    () =>
      verifyAgentRequest(readPres("presentation.http"), {
        resolver: fixtureResolver(),
        fetcher: fixtureFetcher(),
        logger: noopLogger(),
        now: PRES_NOW,
        requireGroundmarkClaim: true,
        // no policy -> nothing would run steps 3–5
      }),
    /requireGroundmarkClaim/,
  );
});

test("adversarial: Groundmark-Claim header absent -> groundmark_claim_missing", async () => {
  const v = await verifyAgentRequest(readPres("missing-groundmark-claim-header.http"), presentationOpts());
  assertRequestFail(v, "groundmark_claim_missing");
});

test("adversarial: header present but not signature-covered -> groundmark_claim_not_covered", async () => {
  const v = await verifyAgentRequest(
    readPres("groundmark-claim-not-in-covered-components.http"),
    presentationOpts(),
  );
  assertRequestFail(v, "groundmark_claim_not_covered");
});

test("adversarial: nonce parameter absent -> nonce_missing", async () => {
  const v = await verifyAgentRequest(readPres("missing-nonce.http"), presentationOpts());
  assertRequestFail(v, "nonce_missing");
});

test("adversarial: claim_type matches no _agentclaim DNS record -> groundmark_claim_dns_mismatch", async () => {
  const v = await verifyAgentRequest(readPres("claim-type-dns-mismatch.http"), presentationOpts());
  // request layer is fine (header present, covered, parseable); the binding fails.
  assert.equal(v.request.ok, true);
  assert.equal(v.ok, false);
  assert.equal(v.attestations?.binding?.ok, false);
  assert.equal(v.attestations?.binding?.reason, "groundmark_claim_dns_mismatch");
});

test("adversarial: ref does not match the attestation endpoint_url -> groundmark_claim_ref_mismatch", async () => {
  const v = await verifyAgentRequest(readPres("ref-attestation-mismatch.http"), presentationOpts());
  assert.equal(v.request.ok, true);
  assert.equal(v.ok, false);
  assert.equal(v.attestations?.binding?.ok, false);
  assert.equal(v.attestations?.binding?.reason, "groundmark_claim_ref_mismatch");
});

test("adversarial: presenting a different claim than the policy requires -> groundmark_claim_policy_mismatch", async () => {
  const store = newNonceStore();
  // Policy requires operator-verified; the holder presents the (genuinely signed)
  // Canadian-presence claim instead. Both claims exist in DNS and verify, but a
  // presentation of a different claim must NOT satisfy the operator-verified
  // requirement. The failure is a claim/policy mismatch, NOT a missing claim
  // (operator-verified is present in DNS and verifies).
  const v = await verifyAgentRequest(readPres("presentation-canadian-presence.http"), presentationOpts({
    nonceStore: store,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
  }));
  assert.equal(v.request.ok, true);
  if (v.request.ok) {
    assert.equal(v.request.groundmarkClaim?.claimType, "x-registry-example-canadian-presence");
  }
  assert.equal(v.ok, false);
  assert.equal(v.attestations?.binding?.ok, false);
  assert.equal(v.attestations?.binding?.reason, "groundmark_claim_policy_mismatch");
  // operator-verified is in DNS and verified, so it is NOT reported as missing.
  assert.deepEqual(v.attestations?.missingClaims, []);
  assert.equal(store.consumed.has("f3a9c21e-4b07-4d8a-b1e2-9c3f0a7e5d12"), false);

  const corrected = await verifyAgentRequest(readPres("presentation.http"), presentationOpts({ nonceStore: store }));
  assert.equal(corrected.ok, true, JSON.stringify(corrected));
  assert.equal(store.consumed.has("f3a9c21e-4b07-4d8a-b1e2-9c3f0a7e5d12"), true);
});

test("adversarial: duplicate Groundmark-Claim headers -> groundmark_claim_duplicate", async () => {
  // Inject a second Groundmark-Claim header into the good presentation. Phase 0
  // permits exactly one; the verifier must reject rather than take the first.
  const good = readPres("presentation.http").toString("latin1");
  const dup = good.replace(
    /(Groundmark-Claim: [^\r\n]*\r\n)/,
    `$1Groundmark-Claim: claim-type="operator-verified"; ref="https://${IDSP}/a/second"\r\n`,
  );
  const v = await verifyAgentRequest(Buffer.from(dup, "latin1"), presentationOpts());
  assertRequestFail(v, "groundmark_claim_duplicate");
});

test("adversarial: replayed presentation reusing a single-use nonce -> nonce_replayed", async () => {
  // One nonce store shared across both presentations, simulating the RP's replay state.
  const store = newNonceStore();
  const first = await verifyAgentRequest(readPres("presentation.http"), presentationOpts({ nonceStore: store }));
  assert.equal(first.ok, true, JSON.stringify(first));

  // nonce-replay.http is byte-identical to the good case: same single-use nonce.
  const replay = await verifyAgentRequest(readPres("nonce-replay.http"), presentationOpts({ nonceStore: store }));
  assertRequestFail(replay, "nonce_replayed");
});

test("adversarial: concurrent valid presentations accept exactly once", async () => {
  const store = newNonceStore();
  const results = await Promise.all([
    verifyAgentRequest(readPres("presentation.http"), presentationOpts({ nonceStore: store })),
    verifyAgentRequest(readPres("presentation.http"), presentationOpts({ nonceStore: store })),
  ]);

  assert.equal(results.filter((v) => v.ok).length, 1, JSON.stringify(results));
  const replay = results.find((v) => !v.ok);
  assert.ok(replay);
  assertRequestFail(replay, "nonce_replayed");
  assert.equal(store.consumed.has("f3a9c21e-4b07-4d8a-b1e2-9c3f0a7e5d12"), true);
});
