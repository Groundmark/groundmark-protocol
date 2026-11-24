import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";

import { LoopbackDnssecResolver, buildQuery, parseAnswer } from "../src/dns/loopbackResolver.ts";

const NAME = "_agentid.agent.example";

interface Reply {
  ad?: boolean;
  rcode?: number;
  /** TXT records, each a list of character-strings. */
  txt?: string[][];
  ttl?: number;
  /** Change the answer: a different ID, a different question name, or no reply at all. */
  wrongId?: boolean;
  otherName?: string;
  silent?: boolean;
}

/** Builds the answer a validating resolver would send to `query`. */
function answer(query: Buffer, r: Reply): Buffer {
  const id = Buffer.from(query.subarray(0, 2));
  if (r.wrongId) id[0] = (id[0] ?? 0) ^ 0xff;
  // The question: from offset 12 to the end of QNAME + 4.
  let q = 12;
  while (query.readUInt8(q) !== 0) q += 1 + query.readUInt8(q);
  let question = query.subarray(12, q + 5);
  if (r.otherName) question = buildQuery(r.otherName, Buffer.from([0, 0])).subarray(12, -11);
  const flags = 0x8000 | 0x0100 | 0x0080 | (r.ad ? 0x0020 : 0) | (r.rcode ?? 0);
  const rrs = (r.txt ?? []).map((strings) => {
    const rdata = Buffer.concat(strings.map((s) => Buffer.concat([Buffer.from([Buffer.byteLength(s)]), Buffer.from(s)])));
    const head = Buffer.alloc(12);
    head.writeUInt16BE(0xc00c, 0); // name: pointer to the question
    head.writeUInt16BE(16, 2);
    head.writeUInt16BE(1, 4);
    head.writeUInt32BE(r.ttl ?? 300, 6);
    head.writeUInt16BE(rdata.length, 10);
    return Buffer.concat([head, rdata]);
  });
  const header = Buffer.alloc(12);
  id.copy(header, 0);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(rrs.length, 6);
  return Buffer.concat([header, question, ...rrs]);
}

/** A DNS-over-TCP server on loopback that answers every query with `reply`. */
async function withServer(reply: Reply, fn: (resolver: LoopbackDnssecResolver) => Promise<void>): Promise<void> {
  const server = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    c.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 2 || buf.length < 2 + buf.readUInt16BE(0)) return;
      if (reply.silent) return;
      const a = answer(buf.subarray(2, 2 + buf.readUInt16BE(0)), reply);
      const len = Buffer.alloc(2);
      len.writeUInt16BE(a.length);
      c.end(Buffer.concat([len, a]));
    });
    c.on("error", () => {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as net.AddressInfo;
  try {
    await fn(new LoopbackDnssecResolver({ port, timeoutMs: 500 }));
  } finally {
    server.close();
  }
}

test("AD set with an answer: secure, records joined per RR, lowest TTL", () =>
  withServer({ ad: true, txt: [["v=gm1; k=ed25519; ", "p=AAAA"], ["other"]], ttl: 120 }, async (r) => {
    assert.deepEqual(await r.resolveTxt(NAME), { status: "secure", records: ["v=gm1; k=ed25519; p=AAAA", "other"], ttl: 120 });
  }));

test("AD not set: insecure (an unsigned zone is never usable)", () =>
  withServer({ ad: false, txt: [["v=gm1; k=ed25519; p=AAAA"]] }, async (r) => {
    const v = await r.resolveTxt(NAME);
    assert.equal(v.status, "insecure");
    assert.ok(!("records" in v));
  }));

test("SERVFAIL: bogus", () =>
  withServer({ rcode: 2 }, async (r) => {
    assert.equal((await r.resolveTxt(NAME)).status, "bogus");
  }));

test("validated NXDOMAIN and NODATA: secure with no records; without AD: insecure", async () => {
  await withServer({ ad: true, rcode: 3 }, async (r) => {
    assert.deepEqual(await r.resolveTxt(NAME), { status: "secure", records: [], ttl: 0 });
  });
  await withServer({ ad: true }, async (r) => {
    assert.deepEqual(await r.resolveTxt(NAME), { status: "secure", records: [], ttl: 0 });
  });
  await withServer({ ad: false, rcode: 3 }, async (r) => {
    assert.equal((await r.resolveTxt(NAME)).status, "insecure");
  });
});

test("an answer with another ID or another question is an error, whatever its AD bit says", async () => {
  await withServer({ ad: true, txt: [["x"]], wrongId: true }, async (r) => {
    assert.equal((await r.resolveTxt(NAME)).status, "error");
  });
  await withServer({ ad: true, txt: [["x"]], otherName: "_agentid.evil.example" }, async (r) => {
    assert.equal((await r.resolveTxt(NAME)).status, "error");
  });
});

test("no answer in time, or nothing listening: error", async () => {
  await withServer({ silent: true }, async (r) => {
    assert.equal((await r.resolveTxt(NAME)).status, "error");
  });
  const closed = new LoopbackDnssecResolver({ port: 1, timeoutMs: 500 });
  assert.equal((await closed.resolveTxt(NAME)).status, "error");
});

test("a resolver that isn't on loopback is refused unless the path is said to be authenticated", () => {
  assert.throws(() => new LoopbackDnssecResolver({ host: "8.8.8.8" }), /not loopback/);
  assert.doesNotThrow(() => new LoopbackDnssecResolver({ host: "10.0.0.53", allowNonLoopback: true }));
  assert.doesNotThrow(() => new LoopbackDnssecResolver({ host: "::1" }));
});

test("the query asks for TXT with DO set; malformed answers are rejected", () => {
  const id = Buffer.from([0x12, 0x34]);
  const q = buildQuery(NAME, id);
  assert.equal(q.readUInt16BE(0), 0x1234);
  assert.equal(q.readUInt16BE(q.length - 4) & 0x8000, 0x8000); // DO bit in the OPT record's flags
  assert.throws(() => parseAnswer(Buffer.alloc(5), id, NAME), /short/);
  const looped = answer(q, { ad: true, txt: [["x"]] });
  looped.writeUInt16BE(0xc000 | 12, 12); // the question's name points at itself
  assert.throws(() => parseAnswer(looped, id, NAME));
  assert.throws(() => buildQuery("bad..name", id), /bad name/);
});

// Against the machine's own validating resolver, when asked: GM_LIVE_DNS=_agentid.<a signed agent domain>
test("live: a real validating resolver on 127.0.0.1", { skip: !process.env.GM_LIVE_DNS && "set GM_LIVE_DNS to a signed _agentid name" }, async () => {
  const r = await new LoopbackDnssecResolver().lookup(process.env.GM_LIVE_DNS ?? "");
  assert.equal(r.status, "secure", JSON.stringify(r));
});

test("structural checks: TC, a missing declared section, trailing bytes, or a dotted single label is an error, even with AD", () => {
  const id = Buffer.from([0x0a, 0x0b]);
  const q = buildQuery(NAME, id);
  const ok = answer(q, { ad: true, txt: [["v=gm1"]] });
  assert.deepEqual(parseAnswer(ok, id, NAME).records, ["v=gm1"]);

  const tc = Buffer.from(ok);
  tc.writeUInt16BE(tc.readUInt16BE(2) | 0x0200, 2);
  assert.throws(() => parseAnswer(tc, id, NAME), /TC/);

  const missingAuthority = Buffer.from(ok);
  missingAuthority.writeUInt16BE(1, 8); // declares one authority record that isn't there
  assert.throws(() => parseAnswer(missingAuthority, id, NAME));

  assert.throws(() => parseAnswer(Buffer.concat([ok, Buffer.from([0])]), id, NAME), /after the declared records/);

  // One label "_agentid.agent.example" (dots inside it) is not the three-label name that was asked.
  const label = Buffer.from(NAME);
  const dotted = Buffer.concat([ok.subarray(0, 12), Buffer.from([label.length]), label, Buffer.from([0, 0, 16, 0, 1])]);
  assert.throws(() => parseAnswer(dotted, id, NAME), /another question/);

  const opcode = Buffer.from(ok);
  opcode.writeUInt16BE(opcode.readUInt16BE(2) | (2 << 11), 2);
  assert.throws(() => parseAnswer(opcode, id, NAME), /opcode/);
});
