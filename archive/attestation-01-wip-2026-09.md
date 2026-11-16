# Groundmark Attestation Framework and Identity Service Provider Profile

**Internet-Draft:** `draft-noss-jeftovic-groundmark-attestation-01`
**Stream:** Independent Submission
**Intended status:** Experimental
**Expires:** 6 March 2027
**Date:** 2 September 2026

**Authors:**
- E. Noss — Groundmark
- M. Jeftovic — easyDNS Technologies Inc.

---

## Abstract

This document defines the Groundmark attestation framework and the profile of Identity Service Providers (IDSPs) that issue Groundmark attestations. It is the companion document to the Groundmark core protocol, which specifies DNS publication and request-signature mechanics. This document specifies the role and obligations of Identity Service Providers, a four-level taxonomy of attestation strength, an initial vocabulary of claim types, the key-bound JSON schema and signature construction for attestation payloads, the method-disclosure discipline that defines an IDSP's accountability obligation, signed status and revocation semantics for the attestation layer, and relying-party issuer authorization requirements.

The core protocol document defines the discovery mechanisms (the `_agentclaim` DNS TXT record and the HTTP retrieval of attestation payloads) on which this document depends. Together the two documents specify Groundmark.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task Force (IETF). Note that other groups may also distribute working documents as Internet-Drafts. The list of current Internet-Drafts is at https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as "work in progress."

This Internet-Draft will expire on 6 March 2027.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document.

## Table of Contents

1. Introduction
   - 1.1. Relationship to the Core Protocol
   - 1.2. Design Principles
   - 1.3. Non-Goals
   - 1.4. Requirements Language
2. Terminology
3. The Identity Service Provider Role
   - 3.1. Method Disclosure
   - 3.2. IDSP Trust Anchors
4. Attestation Level Taxonomy
   - 4.1. Level 0 — Permissionless
   - 4.2. Level 1 — Operator Accountability
   - 4.3. Level 2 — Claim-Specific Verification
   - 4.4. Level 3 — Regulatory-Grade
   - 4.5. Level Stacking and Composability
5. Claim Type Vocabulary
   - 5.1. operator-verified
   - 5.2. age-over-18, age-over-21
   - 5.3. jurisdiction-licensed
   - 5.4. kyc-basic
   - 5.5. kyc-enhanced
   - 5.6. operator-contact
   - 5.7. brand-authorized
6. Attestation Payload Schema
   - 6.1. JSON and Canonicalization Profile
   - 6.2. Transport and Caching
   - 6.3. Top-Level Fields
   - 6.4. Claim Subject Semantics
   - 6.5. The method_disclosure Object
   - 6.6. Worked Example
7. Signature Construction and Verification
   - 7.1. Verification Context and Mandatory Bindings
   - 7.2. Verification Steps
8. Status and Revocation
   - 8.1. Signed Status Object
   - 8.2. Status Verification and Fail Modes
   - 8.3. Audit Logging of Grace Decisions
9. Security Considerations
   - 9.1. Endpoint Portability Attacks
   - 9.2. Display Name and Brand Impersonation
   - 9.3. Cross-Claim Consistency
   - 9.4. IDSP Compromise
   - 9.5. Denial of Service via Status Endpoint
   - 9.6. Method Disclosure Misrepresentation
   - 9.7. Signature Validity Versus Issuer Authorization
   - 9.8. Fetch Hardening
10. Privacy Considerations
    - 10.1. Minimal Disclosure by Construction
    - 10.2. Public Visibility of Attestation Existence
    - 10.3. Linkability Across Relying Parties
11. Governance Considerations
12. Migration Considerations
13. IANA Considerations
    - 13.1. Groundmark Claim Types Registry
    - 13.2. Groundmark Method Identifier Registry
14. References
    - 14.1. Normative References
    - 14.2. Informative References
- Acknowledgements
- Change Log
- Authors' Addresses

---

## 1. Introduction

The Groundmark core protocol [I-D.noss-jeftovic-groundmark-core] specifies how an agent's signing public key and references to externally hosted attestations are published in DNS, and how relying parties verify HTTP request signatures using the published key. The core protocol intentionally treats attestation content as opaque: DNS publishes a reference (either in the clear or as a digest commitment that the agent opens by presenting the URL in a signed request), the relying party retrieves the attestation over HTTPS, and the question of what an attestation says and how it should be evaluated is deferred to this document.

This document specifies that evaluation framework. It defines:

- The role of an Identity Service Provider (IDSP), an entity that verifies a claim about an operator or agent and publishes a signed attestation under the Groundmark framework.
- A four-level taxonomy of attestation strength, from cryptographic-only Level 0 through regulatory-grade Level 3.
- An initial vocabulary of claim types, with structured value schemas and registration policy for extensions.
- The key-bound JSON schema and canonical signature construction for an attestation payload served at the attestation URL that an `_agentclaim` `ref=` field references or commits to.
- The method-disclosure obligation: an IDSP's primary duty is to accurately characterize the verification it performed, not to assert a conclusion. This obligation is what makes Groundmark attestations evaluable rather than reducible to brand recognition.
- Signed status and revocation semantics specific to the attestation layer, including cache freshness and explicit relying-party grace policy for unavailable status endpoints.

The design is informed by Kim Cameron's Laws of Identity [Cameron2005], reframed for a setting in which the principal whose identity is being attested is an organizational operator (or, in the individual-operator case, a hosted-identity provider) rather than a human individual interacting directly.

### 1.1. Relationship to the Core Protocol

This document depends on the core protocol [I-D.noss-jeftovic-groundmark-core] for:

- DNS record format and publication for `_agentclaim` records, in both open and committed reference form.
- DNSSEC requirements for all Groundmark DNS lookups.
- The HTTPS retrieval transport for attestation payloads.
- Request-signature mechanics, against which an attestation is ultimately evaluated.
- The `Groundmark-Claim` header field, through which an agent presents an attestation reference under its request signature, and the binding of that header to `_agentclaim` records before any fetch.

A relying party implementing Groundmark MUST implement the core protocol. Implementing this document additionally is OPTIONAL: a relying party may choose to require only signature verification (Level 0) without evaluating attestations, in which case the mechanisms in this document are not exercised. The core protocol's permissionless default mode remains available to all participants.

### 1.2. Design Principles

The framework defined here is shaped by three principles, in addition to those stated in the core protocol.

- **Authenticate the minimum necessary.** The right attestation level for any transaction is the lowest that meets the relying party's legitimate risk profile. The framework is designed so that most transactions can proceed at Level 0; higher levels are available but not encouraged.
- **IDSPs attest to methods, not conclusions.** An IDSP's primary accountability obligation is to characterize what verification it performed and to stake its reputation on the accuracy of that characterization. The trust decision belongs to the relying party. This is what allows a relying party to make a contextual judgment rather than a binary accept/reject decision based on the IDSP's brand alone.
- **No single point of control.** The framework permits a diversity of IDSPs operating under different trust frameworks, jurisdictions, and competence areas. No central authority designates which IDSPs are authoritative. Recognition of an IDSP for any specific purpose is a property of the relying party's policy and, where applicable, the relying party's regulatory framework.

### 1.3. Non-Goals

This document does not:

- Designate, certify, or otherwise centrally validate IDSPs. The framework specifies what an IDSP does and the obligations it accepts; recognition is a matter of relying-party policy or external trust framework.
- Define the substantive content of any specific regulatory framework. Level 3 attestations may exist within frameworks (for example, FINTRAC PCMLTFA for Canadian KYC, or applicable professional licensing regimes); this document specifies how a Level 3 attestation is structured and verified, not the underlying regulatory standard.
- Replace any existing credential or attestation system. An IDSP MAY use Verifiable Credentials, JWTs, or other formats internally; the Groundmark attestation payload is the format in which an attestation is presented to a Groundmark relying party.

### 1.4. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

## 2. Terminology

The terminology of the core protocol [I-D.noss-jeftovic-groundmark-core] applies. The following additional terms are used in this document.

**Attestation** — A signed statement by an IDSP that a specific claim about an operator or agent has been verified to a stated standard using stated methods. Serialized as a JSON document per Section 6.

**Attestation ID** — A globally unique immutable identifier for a single issued attestation. It is bound into both the signed parent attestation and the signed status object.

**Claim** — A bounded predicate about an operator or agent that an attestation verifies (for example, "the operator has passed FINTRAC tier-basic KYC", or "the operator holds an active real-estate licence in Ontario, Canada").

**Claim Subject** — A machine-readable description of the entity to which a claim applies, including role, entity type, and relationship to the agent.

**Claim Type** — A registered identifier denoting the predicate structure of a claim. The initial vocabulary is defined in Section 5.

**Identity Service Provider (IDSP)** — A trusted third party that performs verification of a claim and publishes a signed attestation. Defined more fully in Section 3.

**Issuer Authorization** — A relying-party policy decision that an IDSP, purpose-scoped signing key, framework, jurisdiction, method profile, claim type, and maximum level are authorized for a specific use.

**Level** — An integer from 0 to 3 indicating the strength of verification associated with a Groundmark attestation, as defined in Section 4.

**Method Disclosure** — The structured description, present in every Groundmark attestation, of the verification methods the IDSP engaged. Defined in Section 3.1.

**Subject Key Thumbprint** — The Agent Key Thumbprint, as defined by the core protocol, for the exact agent signing key to which an attestation is bound.

**Status Object** — An independently signed JSON object that states the current status of an immutable attestation and binds that status to the attestation's identifier and digest.

**Pending Publication** — The pre-active state of an issued attestation whose `_agentclaim` reference, in open or committed form, has not yet been observed in DNS. A pending attestation is not valid for relying-party policy satisfaction.

**Open Claim Reference** — As defined in the core protocol: an `_agentclaim` record whose `ref=` parameter carries the attestation URL.

**Committed Claim Reference** — As defined in the core protocol: an `_agentclaim` record whose `ref=` parameter carries the SHA-256 digest of the attestation URL, opened only by a presented claim carrying the URL.

**Presented Claim** — As defined in the core protocol: an attestation reference carried in a `Groundmark-Claim` header field covered by the request signature.

**Relying Party** — As in the core protocol. In this document's context, a relying party evaluating attestations decides which IDSPs it trusts and for what purposes, and which attestation levels and claim types it requires.

## 3. The Identity Service Provider Role

An IDSP under Groundmark is an entity that:

1. Performs verification of a specific claim about an operator or agent, using methods the IDSP discloses in each attestation it issues.
2. Publishes attestations as signed JSON documents over HTTPS, at the URLs that `_agentclaim` `ref=` fields reference directly or commit to by digest.
3. Publishes separate attestation-signing and status-signing public keys in DNS using the purpose-scoped `_agentid` convention defined by the core protocol, under a DNSSEC-signed zone.
4. Operates a signed status mechanism per Section 8.

Any person, organization, or institution with appropriate competence may operate as an IDSP for claims within its competence. No central designation is required. Recognition of an IDSP by a relying party, or by a regulatory framework whose requirements a relying party is attempting to satisfy, is independent of this specification.

### 3.1. Method Disclosure

An IDSP's primary obligation under Groundmark is method disclosure: each attestation MUST contain a structured description of the verification methods the IDSP performed. This obligation is what distinguishes an IDSP from a conventional certificate authority. A certificate authority asserts a conclusion ("this entity controls this domain"); a Groundmark IDSP asserts a conclusion together with a disclosure of how that conclusion was reached, allowing the relying party to make a contextual trust decision.

The structure of the `method_disclosure` object is specified in Section 6.5. The IDSP is responsible for the accuracy of this disclosure; misrepresentation of methods is the principal failure mode against which the IDSP's reputation is exposed.

### 3.2. IDSP Trust Anchors

This document does not specify how a relying party comes to trust a specific IDSP for a specific purpose. The expected mechanisms include:

- Direct evaluation by the relying party of an IDSP's public practices statement, audit reports, and method disclosures.
- Recognition by a regulator or industry body whose rules the relying party operates under.
- Inclusion in a curated list maintained by a community or trust framework operator.

These are out of scope for this specification. What this specification provides is the substrate that makes any of these evaluation modes possible: every Groundmark attestation includes the IDSP's identity, the methods it performed, and the cryptographic material needed to verify the IDSP's signature. A cryptographically valid signature is necessary but not sufficient for policy acceptance: a relying party MUST separately authorize the issuer for the claim, framework, jurisdiction, method profile, level, and key purpose required by the transaction.

An IDSP MUST use different private keys for `attestation-signing` and `status-signing`. Each public key MUST be published at `_agentid.<idsp>` with a distinct `kid=` and the corresponding `purpose=` value. A relying party MUST select an IDSP key by both identifier and purpose. A key authorized for one purpose MUST NOT satisfy another purpose.

## 4. Attestation Level Taxonomy

Groundmark defines four attestation levels indicating the strength of verification associated with a claim. The level is a floor, not a ceiling: a relying party requiring Level 1 MAY accept a Level 2 or Level 3 attestation for the same claim type. A relying party requiring Level 2 MUST NOT accept a Level 1 attestation in its place.

The levels do not aggregate. Three Level 2 attestations do not constitute a Level 3 attestation. Each claim stands on its own merits.

Levels never substitute for claim types or method profiles. A relying party MUST authorize and require the intended `claim_type`; a numerically higher level attached to a different claim does not satisfy that requirement. A custom claim may use a level only if its claim profile and actual verification meet every baseline requirement of that level. Account or profile control alone is not Level 1 operator accountability.

### 4.1. Level 0 — Permissionless

No attestation required. The relying party verifies an HTTP request signature against the agent's DNSSEC-authenticated key per the core protocol. This establishes current-key provenance only: the request was signed by the private key corresponding to the currently published `_agentid` key selected for the request.

This is the default mode under Groundmark and is expected to cover the majority of agent transactions. Self-asserted `_agentclaim` records using the `val=` form (for example, operator-contact) are Level 0 disclosures: they are operator assertions, not third-party verifications.

A relying party operating at Level 0 CAN conclude that the request was signed by the exact key currently authenticated for the agent domain. It CANNOT conclude anything about the operator's identity, legal standing, location, compliance, brand authorization, or continuity across key changes.

### 4.2. Level 1 — Operator Accountability

A real, identifiable party stands behind the agent. Level 1 establishes that an operator exists, that the operator demonstrably controls the agent domain, and that the operator has accepted accountability under the IDSP's trust framework. The claim is about existence and accountability, not capability or compliance: if something goes wrong, there is a known party to contact.

Required verification, performed by the IDSP:

- **Operator existence:** the operator is a real person or organization.
- **Operational authorization:** for an operator-controlled agent domain, the operator demonstrates domain control using a DNSSEC-authenticated challenge or an equivalently strong method. For a provider-hosted agent domain, the IDSP verifies an authenticated provider binding that explicitly authorizes the hosted agent for the operator.
- **Agent-key binding:** for an operator-controlled key, the operator demonstrates possession of the private key corresponding to the exact `subject_key_thumbprint`. For a provider-custodied key, the custodian demonstrates possession and the IDSP verifies an explicit authorization binding the operator, hosted agent domain, and exact key.
- **Acceptance of terms:** the operator has agreed to the IDSP's accountability framework.

Acceptable methods are at the IDSP's discretion subject to the method-disclosure obligation and relying-party issuer authorization. Typical methods include business registration lookup, DNSSEC domain challenge, agent-key proof of possession, terms acceptance, strong administrator authentication, or credential binding to a verified account. Email confirmation alone is not sufficient for Level 1 issuance.

An IDSP MAY verify and retain operator attributes in a private account before an agent exists. That account state is not a Groundmark attestation. The IDSP MUST NOT issue an `operator-verified` or other Level 1 attestation until it has bound the selected attributes to a specific agent domain and exact agent key using the direct-control or provider-hosted process above.

For a provider-hosted agent, `method_disclosure.executions` MUST identify the hosted-agent binding and key-custody verification methods, including the custodian or hosting-provider domain as a material provider or performer. A relying party can then distinguish direct operator key control from provider custody without exposing the operator's private account evidence.

A relying party operating at Level 1 CAN conclude that an identifiable operator is accountable for the agent's actions, and that the operator accepted terms establishing accountability. It CANNOT conclude that the operator is compliant with any specific regulation or legal standard.

### 4.3. Level 2 — Claim-Specific Verification

A bounded, specific fact about the operator or agent has been attested. Each Level 2 attestation is a single predicate: "the operator is over 18", "the operator holds a valid Ontario real estate licence", "the agent has passed basic financial-services onboarding". The minimal-disclosure principle is operationally critical at this level: the IDSP attests to the predicate, not to the underlying data.

A relying party operating at Level 2 CAN conclude that the stated predicate was verified by a third party to the standard disclosed, and that the IDSP staked its reputation on the accuracy of the attestation. It CANNOT conclude that the claim satisfies a regulatory requirement without also verifying that the IDSP and its methods are recognised by the relevant regulator.

### 4.4. Level 3 — Regulatory-Grade

The attestation meets a specific legal or regulatory standard. Level 3 covers claims that must meet defined legal or regulatory requirements such as Know Your Customer / Anti-Money Laundering verification under a named framework, professional licensure verified against government records, or biometric identity proofing under a named assurance level.

A Level 3 attestation MUST carry the `framework` field (Section 6.3) identifying the regulatory or trust framework under which the attestation is issued. It MUST carry the `jurisdiction` field where the framework is jurisdictionally scoped.

A relying party operating at Level 3 CAN rely on the attestation to satisfy its own regulatory obligations where the relevant trust framework explicitly permits such reliance. The relying party MUST verify that the named IDSP is recognized by the relevant regulator or framework before relying on a Level 3 attestation for compliance purposes; this specification does not designate any IDSP as authoritative for any framework.

### 4.5. Level Stacking and Composability

An agent identity MAY carry multiple `_agentclaim` records simultaneously, each independent. A single agent might present a Level 1 operator-verified attestation alongside several Level 2 claim-specific attestations from different IDSPs. The relying party selects only the claims its policy requires.

Selection works differently for the two reference forms. Open claim references are all visible to the relying party, which chooses among them. A committed claim reference is visible only when presented, and the core protocol permits one presented claim per request in this version. A policy that requires several claims to be evaluated together can therefore be satisfied in a single request only if at most one of them is committed. Operators SHOULD publish as open references any claims that relying parties are expected to evaluate in combination, and SHOULD reserve the committed form for claims whose existence is itself sensitive.

Multiple attestations from different IDSPs do not implicitly refer to the same underlying operator identity, since IDSPs do not coordinate with one another. Section 9.3 addresses this limitation.

## 5. Claim Type Vocabulary

This section defines the initial vocabulary of claim types. Each claim type specifies a claim profile for use in an attestation payload (Section 6). A claim profile defines:

- the JSON structure of the `claim_value` field;
- valid `claim_subject` roles;
- valid `claim_subject` entity types;
- valid `claim_subject` relationships to the agent;
- allowed assurance levels; and
- permitted method profiles, where the claim type requires method-profile restrictions.

Custom claim types MUST use the form `x-<registrant-domain>-<claim-name>`, where `<registrant-domain>` is a domain controlled by the entity defining the claim type. Custom claim types do not require IANA registration; relying parties MUST ignore claim types they do not recognize, per the core protocol.

Claim types intended for broad interoperability SHOULD be registered in the IANA Groundmark Claim Types registry established by this document (Section 13). Unknown claim types MAY be parsed, canonicalized, and cryptographically verified, but MUST NOT satisfy relying-party policy unless the relying party has installed an explicit claim profile for that type.

### 5.1. operator-verified

**Level: 1.**

The IDSP has verified that a real, identifiable operator controls the agent and has accepted the IDSP's accountability terms.

`claim_subject` profile:

- `role`: `operator`
- `entity_type`: `organization`, `natural-person`, or `other`
- `relationship`: `operator-of-agent`

`claim_value`:

```json
{
  "verified": true,
  "operator_asserted_display_name": "Acme Corp"
}
```

`verified` is REQUIRED and MUST be true (an attestation with `verified=false` MUST NOT be issued; such a record should be absent, or, if previously present, revoked).

`operator_asserted_display_name` is OPTIONAL and SHOULD only be included if the operator has explicitly chosen to disclose it publicly. It is operator asserted. Relying parties MUST NOT use `operator_asserted_display_name` as a policy input, a brand-authorization signal, or the basis of any trust or access-control decision. See Section 9.2.

### 5.2. age-over-18, age-over-21

**Level: 2.**

The operator meets the specified age threshold. The claim value is a boolean predicate; the operator's actual age or date of birth is not disclosed.

`claim_subject` profile:

- `role`: `authorized-human`, `beneficiary`, or `intended-recipient`
- `entity_type`: `natural-person`
- `relationship`: one of the relationships registered for the chosen role

`claim_value`:

```json
{ "result": true }
```

An age claim MUST NOT be accepted for a `claim_subject` whose `entity_type` is `organization` or `software-agent`. An age claim about an organization's operator is invalid unless the claim subject identifies the relevant natural person and relationship.

### 5.3. jurisdiction-licensed

**Level: 2 or 3,** depending on the IDSP's method and the framework under which it is operating.

The operator holds a valid licence in a named jurisdiction and practice category. The licence number MUST NOT be included in the claim value.

`claim_subject` profile:

- `role`: `operator` or `authorized-human`
- `entity_type`: `organization` or `natural-person`
- `relationship`: `operator-of-agent` or another claim-type-registered relationship appropriate to the licence

`claim_value`:

```json
{
  "licensed": true,
  "jurisdiction": "CA-ON",
  "licence_category": "real-estate-agent",
  "licence_status": "active"
}
```

`jurisdiction` uses the conventional country-subdivision form (ISO 3166-1 alpha-2, optionally followed by "-" and an ISO 3166-2 subdivision code).

When this claim is published as a Level 3 attestation, the top-level `framework` field of the attestation MUST identify the regulatory licensing framework.

### 5.4. kyc-basic

**Level: 2 or 3.**

The operator has passed a basic Know Your Customer screening.

`claim_subject` profile:

- `role`: `operator`
- `entity_type`: `organization` or `natural-person`
- `relationship`: `operator-of-agent`

`claim_value`:

```json
{
  "passed": true,
  "framework": "FINTRAC-PCMLTFA",
  "tier": "basic"
}
```

The `framework` field inside `claim_value` is REQUIRED for this claim type and identifies the screening framework applied. When the attestation is Level 3, the top-level `framework` field MUST also be present and SHOULD match the `claim_value` `framework`.

### 5.5. kyc-enhanced

**Level: 3.**

The operator has passed an enhanced KYC process, including source-of-funds verification or equivalent under the named framework.

`claim_subject` profile:

- `role`: `operator`
- `entity_type`: `organization` or `natural-person`
- `relationship`: `operator-of-agent`

`claim_value`:

```json
{
  "passed": true,
  "framework": "FINTRAC-PCMLTFA",
  "tier": "enhanced"
}
```

### 5.6. operator-contact

**Level: 0 (self-asserted).**

A self-declared contact point. This claim type MAY be published directly in a `_agentclaim` record using `val=` without a `ref=` URL or `idsp=`, per the core protocol. Relying parties MUST treat it as unverified self-assertion.

`claim_subject` profile:

- `role`: `operator`
- `entity_type`: `organization`, `natural-person`, `software-agent`, or `other`
- `relationship`: `operator-of-agent` or `contact-for-agent`

`claim_value` (when retrieved as an IDSP-issued attestation, which is uncommon for this claim type):

```json
{
  "contact_type": "email",
  "value": "ops@acmecorp.example"
}
```

### 5.7. brand-authorized

**Level: 2 or 3,** depending on the IDSP's method and the framework under which it is operating.

The IDSP has verified that the claim subject is authorized to act under a named brand for the stated scope. This claim is distinct from `operator-verified`; Level 1 operator accountability MUST NOT be interpreted as brand authorization.

`claim_subject` profile:

- `role`: `operator` or `authorized-human`
- `entity_type`: `organization` or `natural-person`
- `relationship`: `operator-of-agent`, `brand-agent`, or another brand-authorization relationship registered by the claim profile

`claim_value`:

```json
{
  "brand_name": "Acme",
  "authorization_scope": "purchasing-agent",
  "authorization_status": "active"
}
```

The claim value MAY include a jurisdiction or framework identifier when brand authority is jurisdictionally scoped. It MUST NOT include unnecessary underlying contract, licence, or personal data.

## 6. Attestation Payload Schema

This section defines the JSON document served by an IDSP at the attestation URL that an `_agentclaim` `ref=` field references or commits to.

### 6.1. JSON and Canonicalization Profile

Groundmark attestation payloads are UTF-8 JSON [RFC8259] constrained by the I-JSON profile [RFC7493] and canonicalized using JCS [RFC8785] for signature verification.

A verifier MUST:

- reject duplicate object member names at every nesting level;
- reject invalid UTF-8 and JSON strings containing lone surrogates;
- reject numbers outside the interoperable range permitted by I-JSON;
- enforce implementation-defined maximum document size and nesting depth before canonicalization;
- use one strict parse tree for schema validation, semantic checks, claim-profile checks, and JCS signature verification;
- avoid Unicode normalization after parsing; and
- not require the wire JSON to arrive in canonical property order.

Unknown fields MAY be present for forward compatibility. They are part of the parsed object and are covered by the signature unless explicitly excluded by a future versioned schema. A verifier that does not understand an unknown field MUST NOT give that field policy effect.

### 6.2. Transport and Caching

The transport for attestation retrieval is HTTPS, per the core protocol. Additional requirements specific to the attestation layer:

- IDSPs MUST serve attestation payloads with `Content-Type: application/json` (or `application/jose+json` for Verifiable Credential or JWT-bearing variants under future extensions).
- IDSPs MUST require no authentication from the relying party. The `ref=` URL functions as an opaque bearer reference. This holds for attestations published under committed claim references as well: their confidentiality comes from the URL never being published, not from access control at the endpoint.
- IDSPs MUST NOT expose any index, listing, or search interface from which attestation URLs can be obtained without already holding them, and MUST NOT derive attestation URL paths from the subject domain, claim type, issuance order, or issuance time. The core protocol's entropy requirement is what makes a committed reference resistant to dictionary attack.
- IDSPs MUST validate TLS at the transport layer per the underlying HTTPS implementation; relying parties MUST validate the attestation endpoint's TLS certificate per [RFC9110].
- IDSPs MUST set HTTP Cache-Control directives [RFC9111] consistent with the attestation's `expires_at` time. IDSPs MUST NOT set max-age values so short as to force effectively per-request attestation revalidation; the framework is designed for cached immutable attestation retrieval. Current validity is determined by the signed status object described in Section 8.
- Relying parties MAY cache attestation payloads up to the lesser of the IDSP-supplied max-age and the attestation's `expires_at` time.

### 6.3. Top-Level Fields

The attestation is a flat JSON [RFC8259] object using snake_case field names. The following fields are defined.

- **schema_version** (REQUIRED, string) — Schema version. The current value is `"1.1"`. Version 1.1 is the first key-bound schema. Relying parties SHOULD reject schema versions they do not understand. Version 1.0 MAY remain verifiable only under an explicit legacy policy and MUST NOT be used to claim continuity across key changes.
- **attestation_id** (REQUIRED, string) — Immutable globally unique identifier for this attestation. A URN UUID form is RECOMMENDED.
- **subject** (REQUIRED, string) — The agent domain this attestation covers, as a lowercase IDNA A-label FQDN with no trailing root label.
- **subject_key_id** (REQUIRED, string) — The agent DNS key identifier, matching the `kid=` value of the `_agentid` record when one is present. If the selected `_agentid` record has no `kid=`, this value MUST be the empty string. This is not the IDSP signing key identifier.
- **subject_key_thumbprint** (REQUIRED, string) — The RFC 7638 SHA-256 JWK thumbprint of the exact Ed25519 agent key to which the attestation is bound, encoded using Base64url without padding. This value MUST equal the Agent Key Thumbprint for the request-signing key verified under the core protocol.
- **claim_type** (REQUIRED, string) — A value from the claim type vocabulary in Section 5, a vendor extension of the form `x-<registrant-domain>-<claim-name>`, or an IANA-registered extension.
- **claim_subject** (REQUIRED, object) — Machine-readable statement of the entity to which the claim applies. See Section 6.4.
- **claim_value** (REQUIRED, object) — The minimal predicate value. Structure is determined by `claim_type`.
- **level** (REQUIRED, integer) — The attestation level (0 through 3). Relying parties MUST reject attestations whose level is below the level required by the relying party's policy.
- **idsp** (REQUIRED, string) — The IDSP's domain name. The IDSP's public signing key MUST be retrievable via the core-protocol `_agentid` convention at `_agentid.<idsp>`.
- **issued_at** (REQUIRED, string) — The time at which the attestation was issued, formatted per [RFC3339].
- **expires_at** (REQUIRED, string) — The time at which the attestation expires, formatted per [RFC3339]. Relying parties MUST reject attestations whose `expires_at` is in the past.
- **method_disclosure** (REQUIRED, object) — Structured description of the verification the IDSP performed. See Section 6.5.
- **endpoint_url** (REQUIRED, string) — The canonical HTTPS URL at which this attestation is served. For an open claim reference it MUST equal the `ref=` URL in the corresponding `_agentclaim` record. For a committed claim reference it MUST equal the presented `ref`, whose SHA-256 digest MUST in turn equal the record's `ref=` value. Bound into the signed payload to prevent portability attacks (see Section 9.1).
- **status_url** (REQUIRED, string) — HTTPS URL for the independently signed status object described in Section 8. Replaces `revocation_endpoint` in schema version 1.1.
- **signing_key_id** (REQUIRED, string) — Identifier of the IDSP attestation-signing key used. Matches the `kid=` value of the corresponding `_agentid` record at the IDSP's domain; that record MUST declare `purpose=attestation-signing`.
- **signature** (REQUIRED, string) — Base64url-encoded [RFC4648] Ed25519 signature over the canonical payload. See Section 7.
- **jurisdiction** (OPTIONAL, string) — Applicable jurisdiction. REQUIRED at Level 3 when the framework is jurisdictionally scoped.
- **framework** (OPTIONAL, string) — Named regulatory or trust framework. REQUIRED at Level 3.

The fields `revocation_endpoint` and `short_lived_token` from schema version 1.0 are not present in schema version 1.1.

### 6.4. Claim Subject Semantics

A `claim_subject` object identifies what entity a claim is about. It has the following fields:

- **role** (REQUIRED, string) — The subject's role in relation to the agent or transaction. Initial values are `agent`, `operator`, `authorized-human`, `beneficiary`, and `intended-recipient`.
- **entity_type** (REQUIRED, string) — The subject's entity type. Initial values are `organization`, `natural-person`, `software-agent`, and `other`.
- **relationship** (REQUIRED, string) — The relationship between the claim subject and the agent or transaction. Initial values include `operator-of-agent`, `contact-for-agent`, and `brand-agent`.

Claim profiles MUST define the permitted combinations of `role`, `entity_type`, `relationship`, `claim_value` schema, allowed levels, and permitted method profiles. A verifier MUST reject a claim whose `claim_subject` is invalid for the `claim_type`. For example, an `age-over-21` claim cannot apply to a corporate operator merely because the corporation operates the agent; it must identify an appropriate natural-person subject and relationship.

### 6.5. The method_disclosure Object

- **profile** (REQUIRED, string) — Identifier of the IDSP practice profile under which the verification was performed.
- **profile_version** (REQUIRED, string) — Version of the practice profile.
- **executions** (REQUIRED, array of objects) — Structured method-execution provenance entries. The array MAY be empty only when the claim profile explicitly permits no method execution, such as a self-asserted Level 0 claim.
- **method_detail** (OPTIONAL, string) — Free-text description providing additional context. Intended for human review, not machine parsing and not sufficient for policy acceptance.

Each entry in `executions` MUST include:

- **method_id** (REQUIRED, string) — A method identifier drawn from the Groundmark Method Identifier registry established by this document (Section 13) or from an explicitly installed extension profile.
- **method_version** (REQUIRED, string) — Version of the method profile, technology, or authoritative-source integration.
- **execution_mode** (REQUIRED, string) — A machine-readable execution mode. This document defines `idsp-direct`, `idsp-operated-technology`, and `authoritative-source-query`, and reserves `idtp-managed-service` for the companion method-provenance specification. `authoritative-source-query` means the IDSP directly controlled the query; an IDTP-controlled query returning a managed result uses `idtp-managed-service` and also populates the source fields.
- **performed_by** (REQUIRED, object) — Function that performed or controlled execution. The object contains `role` (REQUIRED, string), `domain` (REQUIRED, DNS name), and optional purpose-specific `key_id` and `key_thumbprint` strings.
- **performed_at** (REQUIRED, string) — Time at which the method execution was completed, formatted per [RFC3339].
- **valid_until** (OPTIONAL, string) — Time after which the execution can no longer support new issuance without refresh, formatted per [RFC3339].
- **evidence_class** (OPTIONAL, array of strings) — Evidence categories examined, such as `"domain-control"`, `"cryptographic-key-control"`, `"organization-record"`, `"government-issued-id"`, or `"biometric-liveness"`.
- **source_class** (OPTIONAL, string) — Class of authoritative source queried, when applicable.
- **source_domain** (OPTIONAL, string) — Domain of the authoritative source or material data provider, when required by the method profile.
- **source_observed_at** (OPTIONAL, string) — Time at which source data was observed, formatted per [RFC3339].
- **provider** (OPTIONAL, object) — Material technology or service provider when different from `performed_by`. The object contains `domain` (REQUIRED, DNS name) and optional `service` and `version` strings.
- **receipt_digest** (OPTIONAL, string) — Digest of a private signed Method Receipt. This field is REQUIRED for `idtp-managed-service` under the companion method-provenance specification.

For `idsp-operated-technology`, `performed_by.role` is `idsp` and `provider` identifies the material provider. For `authoritative-source-query`, the `source_class`, `source_domain`, and `source_observed_at` fields identify the source and freshness as required by the method profile. The IDSP remains accountable to the relying party for the attestation it signs. Structured method provenance makes material dependencies visible to policy; it does not transfer the IDSP's issuer accountability to a technology provider or subcontractor. The full IDSP/IDTP managed-receipt profile is specified in [I-D.noss-jeftovic-groundmark-idtp-method-provenance].

### 6.6. Worked Example

The following non-normative example illustrates the JSON payload served by an IDSP at the attestation URL that an `_agentclaim` `ref=` field references or commits to. It is the Level 1 operator-verified attestation referenced by the worked example in the core protocol.

```json
{
  "schema_version": "1.1",
  "attestation_id": "urn:uuid:0190fbf6-07f0-7c1c-8a9c-2f35610297a1",
  "subject": "purchasing.acmecorp.example",
  "subject_key_id": "k1",
  "subject_key_thumbprint": "mBk0ZxJ4exAMPLEwBhlM0GOf3a6wS9mO7example8",
  "claim_type": "operator-verified",
  "claim_subject": {
    "role": "operator",
    "entity_type": "organization",
    "relationship": "operator-of-agent"
  },
  "claim_value": {
    "verified": true,
    "operator_asserted_display_name": "Acme Corp"
  },
  "level": 1,
  "idsp": "verify.example.net",
  "issued_at": "2026-05-19T12:00:00Z",
  "expires_at": "2026-12-01T00:00:00Z",
  "method_disclosure": {
    "profile": "groundmark-operator-accountability",
    "profile_version": "1.0",
    "executions": [
      {
        "method_id": "dnssec-domain-challenge",
        "method_version": "1.0",
        "execution_mode": "idsp-direct",
        "performed_by": {
          "role": "idsp",
          "domain": "verify.example.net"
        },
        "performed_at": "2026-05-19T11:48:00Z",
        "evidence_class": [
          "domain-control"
        ]
      },
      {
        "method_id": "agent-key-proof-of-possession",
        "method_version": "1.0",
        "execution_mode": "idsp-direct",
        "performed_by": {
          "role": "idsp",
          "domain": "verify.example.net"
        },
        "performed_at": "2026-05-19T11:52:00Z",
        "evidence_class": [
          "cryptographic-key-control"
        ]
      },
      {
        "method_id": "organization-existence-check",
        "method_version": "1.0",
        "execution_mode": "authoritative-source-query",
        "performed_by": {
          "role": "idsp",
          "domain": "verify.example.net"
        },
        "performed_at": "2026-05-19T11:55:00Z",
        "source_class": "corporate-registry",
        "source_domain": "registry.example.gov",
        "source_observed_at": "2026-05-19T11:55:00Z",
        "evidence_class": [
          "organization-record"
        ]
      },
      {
        "method_id": "terms-accepted",
        "method_version": "1.0",
        "execution_mode": "idsp-direct",
        "performed_by": {
          "role": "idsp",
          "domain": "verify.example.net"
        },
        "performed_at": "2026-05-19T11:57:00Z"
      }
    ],
    "method_detail": "Operator legal entity confirmed against an authoritative business registry; DNSSEC domain challenge, agent-key proof of possession, and terms acceptance completed."
  },
  "endpoint_url": "https://verify.example.net/a/4f9f3e1c7ab93d4f8d22",
  "status_url": "https://verify.example.net/s/4f9f3e1c7ab93d4f8d22",
  "signing_key_id": "idsp-2026-01",
  "framework": "groundmark-poc",
  "jurisdiction": "CA",
  "signature": "MEUCIQ...base64url...=="
}
```

The IDSP's signing public keys are published at `_agentid.verify.example.net`. The relying party retrieves them via a DNSSEC-validating resolver, selects the record with `kid=idsp-2026-01` and `purpose=attestation-signing`, reconstructs the canonical payload using [RFC8785] on the strict parsed object with the `signature` field removed, and verifies the Ed25519 signature against the IDSP's public key. The relying party then verifies all mandatory bindings in Section 7.1, including that `subject_key_id` and `subject_key_thumbprint` match the exact key that verified the presented Groundmark request.

## 7. Signature Construction and Verification

Attestation signatures use Ed25519 [RFC8032]. The signature is computed over a canonical serialization of the attestation payload with the top-level `signature` field removed.

The canonical serialization is JSON Canonicalization Scheme [RFC8785] applied to the strict parsed attestation payload object, omitting the top-level `signature` key. JCS provides a deterministic byte sequence regardless of input ordering or whitespace, removing a class of canonicalization bugs.

The IDSP's public keys are published in DNS using the `_agentid.<idsp-domain>` convention defined by the core protocol. IDSPs MUST sign their zones with DNSSEC. A public key retrieved from a non-DNSSEC-signed zone MUST NOT be used for attestation verification. The `signing_key_id` field in the attestation identifies which of the IDSP's keys was used; this corresponds to the `kid=` field in an `_agentid` record whose `purpose=` is `attestation-signing`.

### 7.1. Verification Context and Mandatory Bindings

Attestation verification is performed in the context of a Groundmark request, a DNS `_agentclaim` record, and, when present, a presented claim carried in the request's `Groundmark-Claim` header field. For a committed claim reference the presented claim has already been bound to the DNS record by digest under the core protocol before the attestation was fetched; the bindings in this section then bind the signed payload to both. A verifier MUST reject the attestation unless all of the following bindings hold after signature verification:

```text
payload.subject == evaluated agent domain
payload.subject_key_id == actual request-signing-key kid, or empty when omitted
payload.subject_key_thumbprint == actual request-signing-key thumbprint
payload.claim_type == DNS _agentclaim claim=, when the record carries claim=
payload.claim_type == presented claim-type, when a claim was presented
payload.idsp == DNS _agentclaim idsp=, when the record carries idsp=
payload.idsp == presented idsp, when the header carries idsp
payload.endpoint_url == DNS ref=, for an open claim reference
payload.endpoint_url == presented ref, when a claim was presented
sha-256(payload.endpoint_url) == DNS ref=, for a committed claim reference
```

At least one of the `claim_type` bindings and at least one of the `endpoint_url` bindings MUST apply; an attestation that reaches this step with neither a DNS `claim=` nor a presented claim type, or with a committed reference and no presented claim, MUST be rejected.

All FQDN comparisons use lowercase IDNA A-label form with no trailing root label. URL comparisons use the exact canonical URL string from the DNS `ref=` value or the presented `ref` after syntax validation; implementations MUST NOT normalize one URL into another in a way that changes octets, authority, path, query, or percent-encoding. The digest comparison for a committed reference is computed over the octets of `payload.endpoint_url` exactly as specified by the core protocol. The request-signing-key identifier and thumbprint are taken from the exact Ed25519 `_agentid` key that verified the request. A `subject_key_id` mismatch is a binding failure even when the thumbprint matches.

The DNS `claim=` and `idsp=` values where present, the signed presentation claim type and IDSP where present, and the signed payload fields MUST all agree before policy evaluation. A mismatch is a cryptographic binding failure, not merely a policy miss. Implementations SHOULD expose distinct diagnostics such as `wrong_subject`, `subject_key_id_mismatch`, `subject_key_mismatch`, `attestation_claim_type_mismatch`, `attestation_idsp_mismatch`, and `endpoint_mismatch`.

### 7.2. Verification Steps

A relying party verifying an attestation payload MUST:

1. For a presented claim, confirm that the presented `ref` matches exactly one `_agentclaim` record under the matching rules of the core protocol before issuing any fetch. A presented URL that matches no record MUST NOT be fetched. Where the matching record omits `idsp=` and the presented claim carries `idsp`, the relying party MAY apply the issuer authorization of step 13 to the presented `idsp` before issuing the fetch.
2. Apply the fetch hardening requirements in Section 9.8 when retrieving the attestation.
3. Enforce response size, content type, and strict UTF-8 handling.
4. Parse JSON with duplicate-member detection and validate the I-JSON profile in Section 6.1.
5. Confirm that `schema_version` is understood and validate the understood schema.
6. Validate the `claim_value` and `claim_subject` against the claim profile for `claim_type`. Unknown claim types MAY continue through cryptographic inspection, but MUST NOT satisfy policy without an installed claim profile.
7. Retrieve the IDSP's `_agentid` record(s) from DNS using a DNSSEC-validating resolver profile conforming to the core protocol. Select the record matching `signing_key_id` and `purpose=attestation-signing`. Reject if no such purpose-matching record exists, if DNSSEC validation fails, or if the IDSP zone is unsigned.
8. Compute the canonical serialization per [RFC8785] on the same strict parsed payload with the top-level `signature` field removed.
9. Verify the Ed25519 signature using the IDSP's public key.
10. Verify the mandatory bindings in Section 7.1.
11. Confirm that `issued_at` is not in the future beyond local clock-skew policy and that `expires_at` is in the future.
12. Retrieve and verify the signed status object according to Section 8.
13. Verify that relying-party issuer authorization permits this IDSP domain and signing key for the claim type, framework, jurisdiction, method profile, and attestation level.
14. Apply the relying party's transaction policy.

A cryptographically valid attestation from an unauthorized issuer MUST NOT satisfy policy. Implementations SHOULD return a structured verification result that distinguishes cryptographic validity from policy satisfaction; for example, a result may indicate that the payload signature and status are valid while reporting `issuer_untrusted`, `issuer_key_untrusted`, `framework_untrusted`, `method_profile_untrusted`, or `level_not_authorized`.

## 8. Status and Revocation

DNS publication withdrawal and authoritative attestation status are complementary but distinct controls.

**DNS publication withdrawal (under the core protocol)** — Removal of the `_agentclaim` record withdraws the operator's current publication of that claim reference after the DNS TTL. It does not alter the attestation, produce a signed lifecycle statement, or prove IDSP revocation.

**Status-layer revocation** — The IDSP changes the signed status object at the attestation's `status_url`. The current `_agentid` key publication remains usable; only the specific attestation status changes. This is the authoritative revocation mechanism for an issued attestation.

### 8.1. Signed Status Object

Schema version 1.1 uses an independently signed status object. The parent attestation is immutable: updating status MUST NOT modify the parent attestation bytes or signature.

The public status endpoint returns a JSON object of the following form:

```json
{
  "schema_version": "1.0",
  "attestation_id": "urn:uuid:0190fbf6-07f0-7c1c-8a9c-2f35610297a1",
  "attestation_digest": "sha-256:W47example8Tsh9Q7cArUePQvZQ6V8_example",
  "status": "active",
  "sequence": 4,
  "this_update": "2026-05-19T12:00:00Z",
  "next_update": "2026-05-19T12:05:00Z",
  "reason_code": null,
  "signing_key_id": "idsp-status-2026-01",
  "signature": "MEUCIQ...base64url...=="
}
```

Fields:

- **schema_version** (REQUIRED, string) — Status object schema version. The current value is `"1.0"`.
- **attestation_id** (REQUIRED, string) — MUST equal the parent attestation's `attestation_id`.
- **attestation_digest** (REQUIRED, string) — SHA-256 digest of the complete immutable canonical parent attestation, including its `signature`, encoded as `sha-256:<base64url>`.
- **status** (REQUIRED, string) — One of `pending_publication`, `active`, `revoked`, `suspended`, `superseded`, or `expired`. `pending_publication` means the attestation has been issued but the IDSP has not yet observed its corresponding DNS `_agentclaim` reference; it MUST NOT satisfy relying-party policy.
- **sequence** (REQUIRED, positive integer) — Monotonically increasing sequence for every status change or refresh. The first status object for an attestation uses sequence 1. Rotation of the status-signing key MUST NOT reset the sequence.
- **this_update** (REQUIRED, string) — Time at which this status object was issued, formatted per [RFC3339].
- **next_update** (REQUIRED, string) — Time after which this status object is no longer fresh, formatted per [RFC3339].
- **reason_code** (REQUIRED, string or null) — Machine-readable reason for non-active status. The value SHOULD be non-null for `revoked`, `suspended`, `superseded`, or `expired`, and SHOULD be null for `active` or `pending_publication`.
- **signing_key_id** (REQUIRED, string) — Identifier of the IDSP status-signing key.
- **signature** (REQUIRED, string) — Base64url-encoded [RFC4648] Ed25519 signature over the canonical status object with the top-level `signature` field removed.

The status-signing public key is discovered using the same DNSSEC-authenticated `_agentid.<idsp>` convention as attestation signing keys. The selected record MUST match `signing_key_id` and declare `purpose=status-signing`. The status-signing key MUST be different from the attestation-signing key. Relying-party issuer policy MUST authorize the selected key for the status-signing purpose.

The status endpoint MUST NOT require authentication from the relying party. It is public and cacheable. CDN caching, connection limits, global volumetric protection, and abuse controls are permitted, but the endpoint MUST NOT behave differently per relying party or become an authorization oracle.

IDSPs SHOULD issue short-lived status freshness windows. A current cached status object is sufficient; a live request on every transaction is not required. Implementation profiles MAY define tighter operational limits; a PoC profile can use a five-minute default and a fifteen-minute hard maximum.

Status transitions for one `attestation_id` MUST obey the following lifecycle:

- `pending_publication` MAY transition to `active`, `revoked`, or `expired`.
- `active` MAY transition to `suspended`, `revoked`, `superseded`, or `expired`.
- `suspended` MAY transition back to `active`, or to `revoked` or `expired`.
- `revoked` is terminal. An IDSP MUST NOT reinstate the same `attestation_id`; it MUST issue a new attestation with a new identifier.
- `superseded` and `expired` are terminal for the same `attestation_id`.

An IDSP MAY refresh a status without changing its value, but every refresh MUST increment `sequence` and update `this_update` and `next_update`. In particular, a revoked status may be refreshed for availability while remaining revoked; refresh does not constitute reinstatement.

### 8.2. Status Verification and Fail Modes

When verifying a schema version 1.1 attestation, a relying party MUST retrieve a current signed status object from `status_url` or from a still-fresh cache entry.

A relying party MUST reject the status object if any of the following is true:

- the status schema version is not understood;
- strict JSON/I-JSON parsing or JCS canonicalization fails;
- the status signature is invalid;
- no DNSSEC-authenticated key matching both `signing_key_id` and `purpose=status-signing` is available, or the key is not authorized for status signing by the relying party's issuer policy;
- `attestation_id` differs from the parent attestation;
- `attestation_digest` differs from the digest of the complete immutable canonical parent attestation, including its signature;
- `sequence` is less than the highest accepted sequence for this attestation across all authorized status-signing keys, or otherwise violates the verifier's replay and cache policy;
- `this_update` is in the future beyond local clock-skew policy;
- `next_update` is in the past;
- `status` is not `active`; or
- the status endpoint response fails the fetch hardening profile in Section 9.8.

Once `next_update` passes, default behavior is fail closed. A relying party MAY configure a bounded grace period only for explicitly identified low-risk operations, only when the most recent cached status object was valid and active, and only with audit logging per Section 8.3. Grace policy is a transaction-specific relying-party decision; it is not automatic at Level 1 or any other level.

### 8.3. Audit Logging of Grace Decisions

Use of a status grace period MUST be logged. The logging requirements below are the minimum; relying parties may impose additional requirements under their own policies.

The log entry MUST include:

- The agent domain, the origin of the attestation's `endpoint_url`, and the SHA-256 digest of the full URL.
- The attestation's `attestation_id`.
- The `idsp`, `claim_type`, and `level` from the attestation.
- The most recent accepted status `sequence`, `this_update`, and `next_update`.
- The reason for grace use, with an indication of the status fetch failure mode.
- The relying-party policy identifier that permitted grace for this transaction.
- The time of the decision.
- The identity of the transaction or operation that proceeded under grace.

The log MUST be retained by the relying party for a period not less than one year, or for the period required by any applicable regulatory framework, whichever is longer. The log SHOULD be available to the IDSP or applicable trust framework on reasonable request, since an unexpected pattern of grace decisions on a particular IDSP is operationally significant.

## 9. Security Considerations

### 9.1. Endpoint Portability Attacks

The `endpoint_url` field in the canonical payload binds an attestation to the specific URL at which it is served. Without this binding, an attacker who obtained a valid attestation payload (perhaps by previously serving as the IDSP under a since-decommissioned identity) could serve that payload at a different location and have it accepted by relying parties. Including `endpoint_url` in the signed canonical payload prevents this attack. Relying parties MUST verify the `endpoint_url` match per Section 7.1; this is not optional.

For a committed claim reference the binding is two-sided. The DNS record commits to the digest of the URL, and the signed payload carries the URL. An attacker who obtained a valid payload cannot serve it at a different location, because `endpoint_url` would not match the location; and an agent cannot present a URL the operator has not authorized, because its digest would match no record. The presented URL is therefore fetched only when both the domain holder, through DNSSEC-signed DNS, and the IDSP, through its signature, agree on it.

### 9.2. Display Name and Brand Impersonation

The `operator_asserted_display_name` field in operator-verified attestations is operator-chosen and self-asserted. The IDSP attesting that the operator exists and is accountable does not, by default, verify that the chosen display name is accurate, non-deceptive, or authorized by a brand owner.

Relying parties MUST NOT use `operator_asserted_display_name` as the basis of trust or access-control decisions. The field is a UI affordance only and should be labeled as operator asserted in user interfaces.

Where brand authority matters, relying parties MUST require an explicit claim such as `brand-authorized` from an issuer authorized for that claim type, method profile, framework, jurisdiction, and level. Brand authority MUST NOT be inferred from Level 1 operator accountability or from the display-name field.

### 9.3. Cross-Claim Consistency

A single agent may carry attestations from multiple IDSPs that implicitly refer to different underlying operator identities, since IDSPs do not coordinate with one another. A relying party evaluating two claims from two different IDSPs cannot, in general, determine whether both claims describe the same operator.

For high-assurance transactions requiring multiple claims, relying parties SHOULD prefer attestations from a single IDSP where possible. Phase 0 relying parties MUST NOT infer common operator identity across IDSPs solely from a shared agent domain or compatible claim subjects. Future versions of this specification may define a framework-scoped, privacy-preserving operator handle that enables cross-claim consistency checks within a trust framework. This is out of scope for this document.

### 9.4. IDSP Compromise

Compromise of an IDSP's attestation-signing key permits an attacker to issue fraudulent attestations until the corresponding `_agentid` record at the IDSP's domain is withdrawn and caches expire. Compromise of a status-signing key permits an attacker to forge lifecycle statements for attestations whose status relies on that key, but the key cannot create a valid parent attestation. Purpose separation limits these blast radii only when verifiers enforce it.

IDSPs MUST protect both key classes with hardware-backed storage where available, audit-grade access controls, and operational controls appropriate to their different signing frequencies. An IDSP SHOULD prepare for emergency rotation under the core protocol and SHOULD publish its rotation policy in its practices statement. Relying parties detecting an attestation-signing-key compromise SHOULD treat all attestations signed under that key as unverifiable until the key is rotated and affected attestations are reissued. A status-signing-key compromise requires rotation of the status key and fresh status objects under the new authorized key; it does not authorize reinstatement of an attestation already known to be revoked.

### 9.5. Denial of Service via Status Endpoint

The status endpoint is a relying-party-facing service consulted directly or through caches for attestation freshness. IDSPs that operate it as an authenticated, throttled, or per-relying-party-rate-limited service shift operational fragility onto the entire relying-party population. This document REQUIRES the status endpoint to be unauthenticated, cacheable, structurally minimal, independently signed, and operated at a service quality appropriate to its function in the trust framework. IDSPs that do not meet this requirement create a denial-of-service vector against deployments depending on their attestations.

### 9.6. Method Disclosure Misrepresentation

The `method_disclosure` object is the central accountability locus of the IDSP role. An IDSP that misrepresents its methods — claiming verification it did not perform, omitting subcontractors, or misstating evidence classes — undermines the trust framework that makes its attestations evaluable. There is no cryptographic mechanism that detects this; the discipline depends on the relying party's, and the broader community's, ability to evaluate IDSP practices and on the IDSP's reputational exposure to inaccurate disclosure. Trust frameworks that recognize specific IDSPs SHOULD require audit of method-disclosure accuracy as a condition of recognition.

### 9.7. Signature Validity Versus Issuer Authorization

Cryptographic validity proves only that the attestation was signed by the private key corresponding to the IDSP key authenticated through DNSSEC. It does not prove that the IDSP is trusted, competent, recognized by a regulator, authorized for the claim type, authorized for the disclosed method profile, authorized in the stated jurisdiction, or authorized up to the attestation's level.

A relying party MUST NOT treat a claim, level, framework, jurisdiction, or method profile as policy-satisfying unless it has explicitly authorized the issuing IDSP and signing key for that use. Such authorization can be local configuration, a regulator or industry-framework bundle, or a signed trust manifest. This document does not require or define one central Groundmark issuer list.

### 9.8. Fetch Hardening

Relying parties commonly fetch attestation and status URLs from server-side infrastructure. A malicious or compromised DNS record, or a URL presented in a `Groundmark-Claim` header field by an untrusted agent, could otherwise turn `ref=` or `status_url` retrieval into a server-side request forgery channel.

A compliant server-side verifier MUST apply a hardened fetch profile to attestation and status retrieval:

- fetch a presented URL only after it has been bound to an `_agentclaim` record under the core protocol, so that every fetched attestation URL was authorized by the domain holder through DNSSEC-signed DNS;
- accept only `https` URLs;
- reject userinfo, fragments, invalid host syntax, ambiguous host syntax, and non-default ports unless an implementation profile explicitly permits a port;
- send no cookies, authorization headers, client certificates, proxy credentials, or ambient application headers;
- send `Accept-Encoding: identity` or enforce a decompressed-size limit;
- resolve all A, AAAA, and CNAME results and reject loopback, private, link-local, multicast, documentation, benchmark, unspecified, reserved, and IPv4-mapped private IPv6 addresses;
- pin the selected public address for the TLS connection while preserving SNI and certificate validation for the original hostname;
- reject redirects unless a future redirect profile repeats every validation step for every hop;
- verify that the connected remote address is the selected address;
- apply connect, response-header, body-idle, and total timeouts;
- enforce implementation-defined maximum body sizes for attestation and status responses;
- perform fetches from an egress-restricted process or network context where practical; and
- log only the URL origin and a digest of the full URL, never token-bearing paths or query strings.

## 10. Privacy Considerations

This document inherits the privacy considerations of the core protocol [I-D.noss-jeftovic-groundmark-core], and is shaped by the guidance of [RFC6973]. The following considerations are specific to the attestation layer.

### 10.1. Minimal Disclosure by Construction

The claim-value structures in Section 5 are deliberately minimal. `age-over-18` discloses a boolean, not a date of birth. `jurisdiction-licensed` discloses the existence and category of a licence in a named jurisdiction, not the licence number. `kyc-basic` and `kyc-enhanced` disclose only that the relevant screening was performed under a named framework.

Custom claim types defined under the `x-<registrant-domain>-<claim-name>` extension mechanism SHOULD follow the same discipline. Claim types that would require disclosure of richer personal data SHOULD be considered carefully against the minimal-disclosure principle and, where possible, decomposed into bounded predicates.

### 10.2. Public Visibility of Attestation Existence

What is publicly visible in DNS for a given agent depends on the reference form the operator chose for each claim.

For an open claim reference, DNS discloses the existence of an attestation of a given `claim_type` from a named `idsp`, plus the `ref=` URL. Anyone who reads the record can follow the URL and read the attestation content, including the claim value, the claim subject, the method disclosure, and any operator-asserted display name. The URL's entropy prevents enumeration of the IDSP's endpoints; it does not restrict who may follow a URL that DNS has already published.

For a committed claim reference, DNS discloses that one authorized attestation exists, together with whichever of `claim_type` and `idsp` the operator chose to retain in the record. The URL, and through it the content, is disclosed only to relying parties the agent presents the claim to. An operator that retains `claim=` and `idsp=` keeps the claim discoverable while withholding its content; an operator that omits both withholds the claim's existence from anyone who has not been presented it.

This is an intentional design tradeoff, exposed to the operator as a per-claim choice. Publishing the claim type and IDSP name supports interoperability, pre-contact evaluation, and meaningful relying-party policy, and is the expected default for organizational deployment. Committing the reference trades that discoverability for control over who learns of the claim. Individual operators concerned about visibility have two independent mitigations (provider-hosted identities and committed references), as discussed in the core protocol's Privacy Considerations.

### 10.3. Linkability Across Relying Parties

A relying party that observes a Groundmark request signature obtains the agent's domain and, on attestation retrieval, the attestation's content. Multiple relying parties observing requests from the same agent can correlate by agent domain. This is a property of DNS-anchored identity and is not unique to Groundmark; an agent domain is necessarily globally unique and linkable.

Operators concerned about cross-relying-party linkability SHOULD provision per-relationship agent domains (for example, distinct subdomains per counterparty) or use ephemeral agent domains. These mitigations come at the cost of reduced amortization of attestation issuance and verification, and are accordingly out of scope for the default deployment pattern.

## 11. Governance Considerations

This specification permits a diversity of IDSP operators, trust frameworks, and jurisdictional regimes. It does not designate any of them.

The framework's accountability properties depend on the existence of mechanisms — external to this specification — for evaluating IDSPs. Such mechanisms may include:

- Industry-specific trust frameworks (analogous to those operated for payment networks, professional licensing bodies, or certificate-authority root programs).
- Regulator-recognized IDSP rosters for specific compliance purposes (for example, recognized KYC providers under a given AML regime).
- Community-curated lists of IDSPs evaluated for specific purposes.
- Direct evaluation by relying parties of an IDSP's public practices statement, audit reports, and method-disclosure accuracy.

The Groundmark framework supports all of these because every attestation carries the IDSP's identity, the methods performed, and the cryptographic material needed to verify the attestation. What this specification provides is the technical substrate that makes governance possible; the governance itself is the work of trust frameworks and the broader community.

Relying-party authorization can be expressed through local configuration, regulator or industry-framework bundles, or signed trust manifests. Such mechanisms SHOULD identify authorized IDSP domains, key identifiers or thumbprints, key purposes, claim types, frameworks, jurisdictions, method profiles, maximum levels, validity periods, sequence numbers, and emergency deny entries. This document does not define a mandatory manifest format or a central Groundmark trust list.

## 12. Migration Considerations

Schema version 1.1 is the first key-bound Groundmark attestation schema. IDSPs issuing new attestations SHOULD issue schema version 1.1. Relying parties MAY continue to verify schema version 1.0 attestations only under an explicit legacy policy.

Migrating from schema version 1.0 to 1.1 requires:

- adding immutable `attestation_id`;
- adding `subject_key_id` and `subject_key_thumbprint`, both bound to the exact agent request-signing key;
- adding machine-readable `claim_subject`;
- replacing `operator_display_name` with `operator_asserted_display_name` where a public display label is needed;
- replacing `revocation_endpoint` and `short_lived_token` with `status_url` and the independently signed status object in Section 8;
- replacing method arrays alone with the structured `method_disclosure.profile`, `profile_version`, and `executions` fields;
- publishing distinct IDSP keys with `purpose=attestation-signing` and `purpose=status-signing`;
- ensuring DNS `claim=` and `idsp=` where present, presented `claim-type`, `idsp`, and `ref` where present, and signed payload fields agree; and
- configuring relying-party issuer authorization for IDSP domain, signing key, claim type, framework, jurisdiction, method profile, and maximum level.

Converting an existing open claim reference to a committed one requires no reissuance: the attestation, its `endpoint_url`, and its status object are unchanged. The operator replaces the record's `ref=` URL with the URL's SHA-256 digest and optionally drops `claim=` and `idsp=`, and the agent begins presenting the URL in a `Groundmark-Claim` header field. Because the URL was previously public, an operator that needs the content to become unreachable by parties who may have recorded the old record SHOULD instead obtain a fresh attestation at a new URL and publish only its digest. Verifiers conforming to earlier versions of the core protocol ignore committed references, so a claim that such verifiers must continue to evaluate has to remain open.

A schema version 1.0 attestation MUST NOT be used to claim continuity across an agent key change. Planned key rotation initially requires attestation reissuance bound to the new `subject_key_thumbprint`; continuity protocols are outside the scope of this document.

## 13. IANA Considerations

### 13.1. Groundmark Claim Types Registry

IANA is requested to establish a new registry titled "Groundmark Claim Types" under a new "Groundmark" registry group.

Registration policy: Specification Required, per [RFC8126]. The designated expert SHOULD evaluate proposed registrations for:

- Adherence to the minimal-disclosure principle.
- Clarity of the `claim_value` schema.
- Clarity of the `claim_subject` role, entity type, and relationship profile.
- Compatibility with the level taxonomy.
- Compatibility with registered or explicitly specified method profiles.

The initial registry contents are the claim types defined in Section 5:

| Claim Type            | Level(s) | Reference     |
| --------------------- | -------- | ------------- |
| operator-verified     | 1        | This document |
| age-over-18           | 2        | This document |
| age-over-21           | 2        | This document |
| jurisdiction-licensed | 2, 3     | This document |
| kyc-basic             | 2, 3     | This document |
| kyc-enhanced          | 3        | This document |
| operator-contact      | 0        | This document |
| brand-authorized      | 2, 3     | This document |

*Table 1: Initial Groundmark Claim Types*

### 13.2. Groundmark Method Identifier Registry

IANA is requested to establish a new registry titled "Groundmark Method Identifiers" under the "Groundmark" registry group.

Registration policy: Specification Required, per [RFC8126].

The initial registry contents are reserved for community development and will be populated by an early companion specification defining the verification method vocabulary and method execution provenance model. Examples of expected initial entries include `dnssec-domain-challenge`, `agent-key-proof-of-possession`, `organization-existence-check`, `terms-accepted`, `corporate-registry-lookup`, `government-issued-id`, `biometric-liveness`, `domain-control-acme`, and `organizational-domain-email-confirmation`.

## 14. References

### 14.1. Normative References

- **[I-D.noss-jeftovic-groundmark-core]** — Noss, E. and M. Jeftovic, "DNS-Anchored Identity Discovery for Autonomous Agents", Work in Progress, Internet-Draft, draft-noss-jeftovic-groundmark-core-01, 2026, <https://datatracker.ietf.org/doc/html/draft-noss-jeftovic-groundmark-core-01>.
- **[I-D.noss-jeftovic-groundmark-idtp-method-provenance]** — Noss, E. and M. Jeftovic, "Groundmark IDSP/IDTP Method Provenance Profile", Work in Progress, Internet-Draft, draft-noss-jeftovic-groundmark-idtp-method-provenance-00, 2026.
- **[RFC2119]** — Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997, <https://www.rfc-editor.org/rfc/rfc2119>.
- **[RFC3339]** — Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339, July 2002, <https://www.rfc-editor.org/rfc/rfc3339>.
- **[RFC4648]** — Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006, <https://www.rfc-editor.org/rfc/rfc4648>.
- **[RFC7493]** — Bray, T., Ed., "The I-JSON Message Format", RFC 7493, March 2015, <https://www.rfc-editor.org/rfc/rfc7493>.
- **[RFC7638]** — Jones, M. and N. Sakimura, "JSON Web Key (JWK) Thumbprint", RFC 7638, September 2015, <https://www.rfc-editor.org/rfc/rfc7638>.
- **[RFC8032]** — Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017, <https://www.rfc-editor.org/rfc/rfc8032>.
- **[RFC8174]** — Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017, <https://www.rfc-editor.org/rfc/rfc8174>.
- **[RFC8259]** — Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017, <https://www.rfc-editor.org/rfc/rfc8259>.
- **[RFC8785]** — Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020, <https://www.rfc-editor.org/rfc/rfc8785>.
- **[RFC9110]** — Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP Semantics", STD 97, RFC 9110, June 2022, <https://www.rfc-editor.org/rfc/rfc9110>.
- **[RFC9111]** — Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP Caching", STD 98, RFC 9111, June 2022, <https://www.rfc-editor.org/rfc/rfc9111>.

### 14.2. Informative References

- **[Cameron2005]** — Cameron, K., "The Laws of Identity", May 2005, <https://www.identityblog.com/?p=352>.
- **[RFC6973]** — Cooper, A., Tschofenig, H., Aboba, B., Peterson, J., Morris, J., Hansen, M., and R. Smith, "Privacy Considerations for Internet Protocols", RFC 6973, July 2013, <https://www.rfc-editor.org/rfc/rfc6973>.
- **[RFC8126]** — Cotton, M., Leiba, B., and T. Narten, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 8126, June 2017, <https://www.rfc-editor.org/rfc/rfc8126>.

## Acknowledgements

The authors thank Doc Searls for substantive review of earlier drafts, the late Kim Cameron whose Laws of Identity [Cameron2005] shaped the philosophical commitments of this work, and the broader registrar, DNS, and identity communities whose infrastructure and prior art make this approach viable.

## Change Log

### -01

- Defined schema version 1.1 with immutable attestation IDs, claim subjects, exact request-key thumbprint binding, and status URLs.
- Added mandatory attestation bindings for subject, request-signing key identifier and thumbprint, DNS claim, DNS IDSP, and endpoint URL.
- Replaced mutable `short_lived_token` and `revocation_endpoint` semantics with independently signed, cacheable status objects that fail closed by default after freshness expiry.
- Defined purpose-separated IDSP attestation and status keys, the `pending_publication` state, terminal revocation, reversible suspension, and monotonic status refresh.
- Clarified private pre-agent operator verification, direct and provider-hosted binding, and the requirement that custom Level 1 claims meet the Level 1 accountability baseline.
- Aligned the method-execution object with the IDSP/IDTP method-provenance profile.
- Required strict UTF-8/I-JSON parsing, duplicate-member rejection, and one parse tree for schema, semantics, and JCS verification.
- Added issuer authorization requirements so valid signatures do not automatically satisfy relying-party policy.
- Renamed display-name semantics to operator-asserted display name and added `brand-authorized` as a separate claim type.
- Added claim-subject profiles, migration guidance from 1.0 to 1.1, and server-side fetch hardening requirements.
- Aligned with committed claim references in the core protocol: `endpoint_url` binds to the DNS URL for an open reference and to the presented URL, whose digest binds to DNS, for a committed one; `claim_type` and `idsp` bind to DNS only where the record carries them and to the presented claim where one is present.
- Added a pre-fetch step requiring a presented URL to be bound to an `_agentclaim` record before retrieval, and extended fetch hardening to presented URLs.
- Required IDSPs to expose no listing of attestation URLs and to derive no URL path from enumerable values, since a committed reference's confidentiality rests on URL entropy.
- Rewrote the public-visibility privacy consideration around the per-claim choice between open and committed references, and documented the level-stacking limit of one presented claim per request.

### -00

- Initial submission as the companion to [I-D.noss-jeftovic-groundmark-core].
- Split from the prior single-draft draft-noss-groundmark-agent-identity-dns.
- Replaced the open-ended methods array description with explicit reference to the Groundmark Method Identifier registry.
- Specified canonical-serialization using JCS [RFC8785], replacing ad-hoc "lexicographically sorted keys" language.
- Tightened revocation fail-mode semantics: prescriptive logging at every fail-open decision; mandated unauthenticated revocation endpoint to prevent DoS leverage.
- Added short-lived status tokens as an OPTIONAL mechanism.
- Resolved IDSP key rotation through the core protocol's "kid=" mechanism rather than as an open question.
- Added Privacy Considerations and Governance Considerations sections.

## Authors' Addresses

**Elliot Noss**
Groundmark
Email: elliot@noss.org
URI: https://groundmark.org

**Mark Jeftovic**
easyDNS Technologies Inc.
Email: markjr@easydns.com
