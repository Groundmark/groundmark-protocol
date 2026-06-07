#!/usr/bin/env python3
"""Groundmark Level 1 PoC fixture generator.

This is INCIDENTAL TOOLING, not the verification library. Its language (Python +
`cryptography`) implies nothing about the library's eventual runtime, which is
undecided. It builds only the runtime-agnostic "world the verifier runs against":
keypairs, DNS TXT record values, signed attestation JSON, the matching revocation
responses, an adversarial fixture corpus, and an RFC 9421 signed-request vector.

Authoritative sources (the drafts win over any prose elsewhere):
  - core draft        — DNS record wire formats (Section 4), request auth (Section 5)
  - attestation draft — attestation JSON schema (Section 6), signing (Section 7)

Run from the poc/ directory:
    python3 tools/generate.py

Reproducible: existing private keys are reused (committed public keys stay stable),
timestamps and ref= tokens are fixed, so re-running yields byte-identical output.
"""
import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

POC = Path(__file__).resolve().parent.parent
KEYS = POC / "keys"
DNS = POC / "dns"
ATT = POC / "attestations"
FIX = POC / "fixtures"

CONFIG = json.loads((POC / "config.json").read_text())
AGENT_DOMAIN = CONFIG["AGENT_DOMAIN"]
IDSP_DOMAIN = CONFIG["IDSP_DOMAIN"]
ISSUER_BASE_URL = CONFIG["ISSUER_BASE_URL"].rstrip("/")

# Fixed values keep regenerated fixtures byte-stable across runs.
TTL = 300
IDSP_KID = "k1"
ISSUED_AT = "2026-05-19T12:00:00Z"
EXPIRES_AT = "2026-12-01T00:00:00Z"          # future relative to the PoC date (2026-06)
EXP_HINT = "2026-12-01"                       # _agentclaim exp= hint (core ABNF date-value)
PAST_EXPIRES_AT = "2026-01-01T00:00:00Z"     # adversarial 'expired' case


# --- encoding helpers --------------------------------------------------------

def b64url(b: bytes) -> str:
    """Base64url, no padding (RFC 4648) — the encoding used for p= and signatures."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    """JCS-equivalent canonicalization for our payloads.

    Exactly equivalent to RFC 8785 (JCS) ONLY because every fixture here uses
    ASCII keys and contains only strings, booleans, and small integers — no
    floats, no non-ASCII. The PRODUCTION verification library MUST use a real
    RFC 8785 implementation; this shortcut is a fixture-only convenience.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# --- keys --------------------------------------------------------------------

def load_or_create_key(name: str) -> Ed25519PrivateKey:
    """Load an existing private key, or generate and persist a new one.

    Reuse keeps the committed public keys (and every signature derived from them)
    stable across regenerations.
    """
    path = KEYS / f"{name}.private.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    os.chmod(path, 0o600)
    return key


def raw_pub_b64url(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)  # 32 bytes
    return b64url(raw)


# --- attestation signing -----------------------------------------------------

def sign(att: dict, idsp_key: Ed25519PrivateKey) -> dict:
    """Return a copy of `att` with an Ed25519 `signature` over the JCS payload
    (signature field removed), per attestation draft Section 7."""
    payload = {k: v for k, v in att.items() if k != "signature"}
    out = dict(att)
    out["signature"] = b64url(idsp_key.sign(canonical(payload)))
    return out


def ref_token(claim_type: str) -> str:
    """Deterministic 128-bit ref= path token so committed fixtures stay byte-stable.

    PRODUCTION MUST use a CSPRNG with >=128 bits of entropy (core draft 4.2.2 /
    7.4). Deriving the token from public inputs here is acceptable ONLY because
    these are non-confidential test fixtures.
    """
    seed = f"{AGENT_DOMAIN}|{claim_type}".encode()
    return b64url(hashlib.sha256(seed).digest()[:16])  # 16 bytes = 128 bits


def att_urls(claim_type: str):
    tok = ref_token(claim_type)
    return f"{ISSUER_BASE_URL}/a/{tok}", f"{ISSUER_BASE_URL}/r/{tok}"


# --- the two good-case attestations (unsigned payloads) -----------------------

def operator_verified_payload() -> dict:
    endpoint, revocation = att_urls("operator-verified")
    return {
        "schema_version": "1.0",
        "subject": AGENT_DOMAIN,
        "claim_type": "operator-verified",
        "claim_value": {
            "verified": True,
            # Informational only; relying parties MUST NOT use as a trust basis
            # (attestation draft 9.2). Operator-chosen, self-asserted.
            "operator_display_name": "Groundmark PoC Operator",
        },
        "level": 1,
        "idsp": IDSP_DOMAIN,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "method_disclosure": {
            "methods": [
                "corporate-registry-lookup",
                "organizational-domain-email-confirmation",
            ],
            "method_detail": (
                "Operator legal entity confirmed against a corporate registry; "
                "domain control confirmed by email challenge to "
                f"postmaster@{AGENT_DOMAIN}."
            ),
            "evidence_class": ["corporate-registry", "domain-control"],
        },
        "endpoint_url": endpoint,
        "revocation_endpoint": revocation,
        "signing_key_id": IDSP_KID,
    }


def canadian_presence_payload() -> dict:
    endpoint, revocation = att_urls("x-registry-example-canadian-presence")
    return {
        "schema_version": "1.0",
        "subject": AGENT_DOMAIN,
        # Custom claim type. Attestation draft 5 writes x-<registrant-domain>-<name>
        # (implying dots, e.g. registry.example), but the core ABNF x-token forbids dots.
        # We use dots->hyphens. SEE README "Open spec items".
        "claim_type": "x-registry-example-canadian-presence",
        "claim_value": {"present": True, "jurisdiction": "CA"},
        "level": 1,
        "idsp": IDSP_DOMAIN,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        # Top-level jurisdiction is OPTIONAL at Level 1 (REQUIRED only at Level 3).
        "jurisdiction": "CA",
        "method_disclosure": {
            # PLACEHOLDER method identifiers — method vocabulary is deferred to the
            # registry (attestation draft 12.2). SEE README "Open spec items".
            "methods": ["self-asserted-presence", "postal-address-verified"],
            "method_detail": (
                "Canadian presence per registrant requirements. PLACEHOLDER "
                "methods/evidence; vocabulary deferred to the Groundmark Method "
                "Identifier registry."
            ),
            "evidence_class": ["postal-address"],
        },
        "endpoint_url": endpoint,
        "revocation_endpoint": revocation,
        "signing_key_id": IDSP_KID,
    }


# --- writers -----------------------------------------------------------------

def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


def write_text(path: Path, text: str) -> None:
    path.write_text(text if text.endswith("\n") else text + "\n")


def revocation_response(revoked: bool) -> dict:
    return {"revoked": revoked}


# --- RFC 9421 signed-request vector (stretch) --------------------------------

def build_signed_request(agent_key: Ed25519PrivateKey):
    """Static RFC 9421 request signature vector signed with the AGENT key.

    No `Agent-Identity` header exists — request auth is RFC 9421 (core draft 5).
    Covers @method, @authority, @target-uri, content-digest (core draft 5.3).
    """
    body = b'{"sku":"X-42","quantity":3}'
    # Content-Digest uses STANDARD base64 (RFC 9530 sf-binary), unlike p=/signature.
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
    content_digest = f"sha-256=:{digest}:"

    method = "POST"
    authority = "api.supplier.example"
    target_uri = "https://api.supplier.example/orders"
    created = 1747654321
    expires = created + 300
    label = "gm"
    covered = '("@method" "@authority" "@target-uri" "content-digest")'
    sig_params = (
        f'{covered};created={created};expires={expires};'
        f'keyid="{AGENT_DOMAIN}";alg="ed25519"'
    )
    # RFC 9421 signature base: one line per covered component, @signature-params last.
    sig_base = "\n".join([
        f'"@method": {method}',
        f'"@authority": {authority}',
        f'"@target-uri": {target_uri}',
        f'"content-digest": {content_digest}',
        f'"@signature-params": {sig_params}',
    ])
    # Signature header value is STANDARD base64 (sf-binary), inside colons.
    sig = base64.b64encode(agent_key.sign(sig_base.encode())).decode()

    http = (
        f"POST /orders HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Digest: {content_digest}\r\n"
        f"Signature-Input: {label}={sig_params}\r\n"
        f"Signature: {label}=:{sig}:\r\n"
        f"\r\n"
    ).encode() + body
    return http, sig_base


# --- main --------------------------------------------------------------------

def main() -> None:
    agent_key = load_or_create_key("agent")
    idsp_key = load_or_create_key("idsp")

    agent_pub = raw_pub_b64url(agent_key)
    idsp_pub = raw_pub_b64url(idsp_key)

    # Committed public key material (private keys stay gitignored).
    write_text(KEYS / "agent.pub.b64url", agent_pub)
    write_text(KEYS / "idsp.pub.b64url", idsp_pub)

    # --- DNS records (core draft 4) ---
    agent_id_rec = f'"v=gm1; k=ed25519; p={agent_pub}"'
    idsp_id_rec = f'"v=gm1; k=ed25519; kid={IDSP_KID}; p={idsp_pub}"'

    ov_ref, _ = att_urls("operator-verified")
    cp_ref, _ = att_urls("x-registry-example-canadian-presence")
    claim_ov = (f'"v=gm1; claim=operator-verified; idsp={IDSP_DOMAIN}; '
                f'ref={ov_ref}; exp={EXP_HINT}"')
    claim_cp = (f'"v=gm1; claim=x-registry-example-canadian-presence; idsp={IDSP_DOMAIN}; '
                f'ref={cp_ref}; exp={EXP_HINT}"')

    write_text(DNS / f"_agentid.{AGENT_DOMAIN}.txt",
               f"_agentid.{AGENT_DOMAIN}. {TTL} IN TXT {agent_id_rec}")
    write_text(DNS / f"_agentid.{IDSP_DOMAIN}.txt",
               f"_agentid.{IDSP_DOMAIN}. {TTL} IN TXT {idsp_id_rec}")
    write_text(DNS / f"_agentclaim.{AGENT_DOMAIN}.txt",
               f"_agentclaim.{AGENT_DOMAIN}. {TTL} IN TXT {claim_ov}\n"
               f"_agentclaim.{AGENT_DOMAIN}. {TTL} IN TXT {claim_cp}")

    # --- good attestations + revocation responses ---
    ov = sign(operator_verified_payload(), idsp_key)
    cp = sign(canadian_presence_payload(), idsp_key)

    write_json(ATT / "operator-verified.json", ov)
    write_json(ATT / "operator-verified.revocation.json", revocation_response(False))
    write_json(ATT / "x-registry-example-canadian-presence.json", cp)
    write_json(ATT / "x-registry-example-canadian-presence.revocation.json", revocation_response(False))

    # good fixtures mirror the served attestations
    write_json(FIX / "good" / "operator-verified.json", ov)
    write_json(FIX / "good" / "x-registry-example-canadian-presence.json", cp)

    # --- adversarial corpus: each a minimal mutation of the good operator-verified ---
    adv = FIX / "adversarial"

    # expired: valid + correctly signed, expires_at in the past
    p = operator_verified_payload(); p["expires_at"] = PAST_EXPIRES_AT
    write_json(adv / "expired.json", sign(p, idsp_key))

    # wrong-subject: subject != agent domain, re-signed so only the binding is wrong
    p = operator_verified_payload(); p["subject"] = "agent.attacker.example"
    write_json(adv / "wrong-subject.json", sign(p, idsp_key))

    # bad-signature: valid payload, one signature byte flipped (NOT re-signed)
    tampered = dict(ov)
    sig_bytes = bytearray(b64url_decode(ov["signature"]))
    sig_bytes[0] ^= 0x01
    tampered["signature"] = b64url(bytes(sig_bytes))
    write_json(adv / "bad-signature.json", tampered)

    # endpoint-mismatch: endpoint_url != ref= it is served from (portability attack)
    p = operator_verified_payload()
    p["endpoint_url"] = f"{ISSUER_BASE_URL}/a/{ref_token('operator-verified')}-PORTED"
    write_json(adv / "endpoint-mismatch.json", sign(p, idsp_key))

    # revoked: a valid attestation paired with a {"revoked": true} response
    write_json(adv / "revoked.json", ov)
    write_json(adv / "revoked.revocation.json", revocation_response(True))

    # unknown-schema-version: a schema_version the verifier must not accept
    p = operator_verified_payload(); p["schema_version"] = "2.0"
    write_json(adv / "unknown-schema-version.json", sign(p, idsp_key))

    # below-policy-level: level below the policy floor (harness requires >= 1)
    p = operator_verified_payload(); p["level"] = 0
    write_json(adv / "below-policy-level.json", sign(p, idsp_key))

    # --- RFC 9421 signed-request vector ---
    http, sig_base = build_signed_request(agent_key)
    (FIX / "request" / "signed-request.http").write_bytes(http)
    write_text(FIX / "request" / "signature-base.txt", sig_base)

    print("Generated:")
    print(f"  keys/        agent.pub.b64url, idsp.pub.b64url (private keys gitignored)")
    print(f"  dns/         3 record files")
    print(f"  attestations/  2 attestations + 2 revocation responses")
    print(f"  fixtures/good/         2")
    print(f"  fixtures/adversarial/  7 cases (+ revoked.revocation.json)")
    print(f"  fixtures/request/      RFC 9421 vector")


if __name__ == "__main__":
    main()
