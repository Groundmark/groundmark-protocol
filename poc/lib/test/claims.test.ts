import { test } from "node:test";
import assert from "node:assert/strict";

import { parseAgentClaim } from "../src/claim/parseAgentClaim.ts";
import { resolveClaims } from "../src/claim/resolveClaims.ts";
import { MockDnssecResolver } from "../src/dns/mockResolver.ts";
import { fixtureResolver } from "./helpers.ts";

const AGENT = "agent.groundmark-poc.example";
const IDSP = "idsp.groundmark-poc.example";

test("parses a ref-form claim record", () => {
  const rec = parseAgentClaim(
    `v=gm1; claim=operator-verified; idsp=${IDSP}; ref=https://${IDSP}/a/vr7Z_bv-gKX0q0cz3wFgug; exp=2026-12-01`,
  );
  assert.deepEqual(rec, {
    kind: "ref",
    claimType: "operator-verified",
    idsp: IDSP,
    ref: `https://${IDSP}/a/vr7Z_bv-gKX0q0cz3wFgug`,
    exp: "2026-12-01",
  });
});

test("parses a val-form (self-asserted) claim record", () => {
  const rec = parseAgentClaim("v=gm1; claim=operator-contact; val=ops@acmecorp.example");
  assert.deepEqual(rec, {
    kind: "val",
    claimType: "operator-contact",
    value: "ops@acmecorp.example",
  });
});

test("invalid shapes are ignored (null), not errors", () => {
  // missing version
  assert.equal(parseAgentClaim("claim=x; val=y"), null);
  // ref without idsp
  assert.equal(parseAgentClaim("v=gm1; claim=x; ref=https://e/a/1"), null);
  // ref + val both present
  assert.equal(parseAgentClaim("v=gm1; claim=x; idsp=e; ref=https://e/a/1; val=z"), null);
  // val + idsp present
  assert.equal(parseAgentClaim("v=gm1; claim=x; idsp=e; val=z"), null);
  // neither ref nor val
  assert.equal(parseAgentClaim("v=gm1; claim=x"), null);
  // missing claim
  assert.equal(parseAgentClaim("v=gm1; val=z"), null);
  // non-https ref
  assert.equal(parseAgentClaim("v=gm1; claim=x; idsp=e; ref=http://e/a/1"), null);
});

test("unrecognized claim type still parses (forward compat)", () => {
  const rec = parseAgentClaim("v=gm1; claim=x-vendor-future-thing; idsp=e; ref=https://e/a/abc");
  assert.ok(rec && rec.kind === "ref" && rec.claimType === "x-vendor-future-thing");
});

test("resolveClaims returns both stacked claims from the fixture zone", async () => {
  const r = fixtureResolver();
  const claims = await resolveClaims(r, AGENT);
  assert.equal(claims.length, 2);
  const types = claims.map((c) => c.claimType).sort();
  assert.deepEqual(types, ["operator-verified", "x-registry-example-canadian-presence"]);
  for (const c of claims) assert.equal(c.kind, "ref");
});

test("resolveClaims treats a non-secure DNSSEC status as absent (empty)", async () => {
  const r = new MockDnssecResolver().setFailure(`_agentclaim.${AGENT}`, "insecure");
  assert.deepEqual(await resolveClaims(r, AGENT), []);
});
