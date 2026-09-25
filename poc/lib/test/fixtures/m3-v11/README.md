# Schema 1.1 interoperability vectors

Generated with `npm run build && node scripts/generate-v11-fixtures.mjs`.
Protocol revision: b9a879ac8e9d1354a41daf4177e7fb7f886389a5.
These are explicitly simulated test executions, not production identity evidence.
The script uses public test seeds, including a fixed status seed; normal key
registration rejects their public keys. No production key belongs in this corpus.

The manifest records public keys, agent binding, canonical SHA-256 digests and
signatures. Each claim has canonical attestation and unsigned signature-input
bytes, plus pending (sequence 1), active (2), revoked (3) status objects. The
separate relying-party verifier consumes identical copies, not its own generated
positive fixtures. Negative vectors alter one condition and assert named failures.

Legacy 1.0 fixtures in the parent directory are preserved as historical inputs.

Source engine: enoss1/groundmark-reference-idsp at `1a53e2f7a99b6f52d364d6f651cc19ba1633a345`, fixtures/v1.1.
All JSON files are byte-identical to that commit.
