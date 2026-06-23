import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseSignatureInput,
  parseSignature,
  paramString,
  paramInteger,
} from "../src/rfc9421/parse.ts";
import { parseHttpRequest } from "../src/rfc9421/message.ts";
import { buildSignatureBase } from "../src/rfc9421/signatureBase.ts";
import { VerificationError } from "../src/errors.ts";
import { readPoc, readPocText } from "./helpers.ts";

const SIG_INPUT =
  'gm=("@method" "@authority" "@target-uri" "content-digest");created=1747654321;expires=1747654621;keyid="agent.groundmark-poc.example";alg="ed25519"';

test("parses the fixture Signature-Input: components, params, verbatim @signature-params", () => {
  const { entries } = parseSignatureInput(SIG_INPUT);
  const gm = entries.get("gm");
  assert.ok(gm, "label gm present");
  assert.deepEqual(
    gm.components.map((c) => c.name),
    ["@method", "@authority", "@target-uri", "content-digest"],
  );
  assert.equal(paramInteger(gm.params, "created"), 1747654321);
  assert.equal(paramInteger(gm.params, "expires"), 1747654621);
  assert.equal(paramString(gm.params, "keyid"), "agent.groundmark-poc.example");
  assert.equal(paramString(gm.params, "alg"), "ed25519");
  // verbatim value reused for the signature base
  assert.equal(gm.rawParamsValue, SIG_INPUT.slice("gm=".length));
});

test("reconstructed signature base is byte-identical to the fixture", () => {
  const http = readPoc("fixtures", "request", "signed-request.http");
  const expected = readPocText("fixtures", "request", "signature-base.txt").replace(/\n$/, "");

  const msg = parseHttpRequest(http);
  const { entries } = parseSignatureInput(
    msg.headers.get("signature-input")![0]!,
  );
  const base = buildSignatureBase(entries.get("gm")!, msg);
  assert.equal(base, expected);
});

test("parses the fixture Signature into raw bytes (Ed25519 = 64 bytes)", () => {
  const http = readPoc("fixtures", "request", "signed-request.http");
  const msg = parseHttpRequest(http);
  const { signatures } = parseSignature(msg.headers.get("signature")![0]!);
  const sig = signatures.get("gm");
  assert.ok(sig);
  assert.equal(sig.length, 64);
});

test("keyid with #kid form parses (FQDN + opaque id)", () => {
  const { entries } = parseSignatureInput(
    'sig1=("@method");created=1;keyid="purchasing.acmecorp.example#k2";alg="ed25519"',
  );
  assert.equal(
    paramString(entries.get("sig1")!.params, "keyid"),
    "purchasing.acmecorp.example#k2",
  );
});

test("commas inside quoted param values do not split the dictionary", () => {
  const { entries } = parseSignatureInput(
    'a=("@method");created=1;keyid="x";tag="one,two", b=("@path");created=2;keyid="y"',
  );
  assert.equal(entries.size, 2);
  assert.equal(paramString(entries.get("a")!.params, "tag"), "one,two");
});

test("malformed Signature-Input rejected with sig_input_malformed", () => {
  for (const bad of [
    "",
    "gm",              // bare key, no value
    'gm="not-a-list"', // value is not an inner list
    'gm=("@method"',   // unterminated list
  ]) {
    assert.throws(
      () => parseSignatureInput(bad),
      (e: unknown) =>
        e instanceof VerificationError && e.reason === "sig_input_malformed",
      `expected sig_input_malformed for: ${JSON.stringify(bad)}`,
    );
  }
});

test("malformed Signature rejected with sig_malformed", () => {
  for (const bad of ["", "gm=notbytes", "gm="]) {
    assert.throws(
      () => parseSignature(bad),
      (e: unknown) => e instanceof VerificationError && e.reason === "sig_malformed",
    );
  }
});
