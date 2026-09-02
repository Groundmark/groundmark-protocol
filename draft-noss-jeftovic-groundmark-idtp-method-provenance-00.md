# Groundmark IDSP/IDTP Method Provenance Profile

**Internet-Draft:** `draft-noss-jeftovic-groundmark-idtp-method-provenance-00`
**Stream:** Independent Submission
**Intended status:** Experimental
**Expires:** 6 March 2027
**Date:** 2 September 2026

**Authors:**
- E. Noss - Groundmark
- M. Jeftovic - easyDNS Technologies Inc.

---

## Abstract

This document defines a Groundmark method-provenance profile for Identity Service Providers (IDSPs) and Identity Technology Providers (IDTPs). It treats IDSP and IDTP as protocol functions rather than mutually exclusive organization classes. The profile defines method execution modes, structured public method provenance, private signed method receipts for managed IDTP execution, role-separated keys, role-scoped relying-party authorization, dependency indexing, incident propagation, and privacy requirements. It is intended to extend the Groundmark attestation framework without transferring the IDSP's accountability to technology providers or exposing raw verification evidence.

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
   - 1.1. Relationship to Groundmark Attestations
   - 1.2. Non-Goals
   - 1.3. Requirements Language
2. Terminology
3. Functional Roles and Accountability
   - 3.1. IDSP Function
   - 3.2. IDTP Function
   - 3.3. Non-Delegable Issuer Accountability
4. Method Execution Provenance
   - 4.1. Execution Modes
   - 4.2. Execution Object
   - 4.3. Performer and Provider Semantics
5. Private Signed Method Receipts
   - 5.1. Receipt Schema
   - 5.2. Receipt Signature and Canonicalization
   - 5.3. Replay and Single-Use Semantics
   - 5.4. IDSP Verification and Retention
6. Public Attestation Disclosure
7. Role-Separated Keys and Trust Policy
8. Dependency Indexing and Incident Propagation
9. Security and Privacy Considerations
10. IANA Considerations
11. References
    - 11.1. Normative References
    - 11.2. Informative References
- Acknowledgements
- Change Log
- Authors' Addresses

---

## 1. Introduction

Groundmark attestations disclose how an IDSP verified a claim. In simple deployments the IDSP performs every method itself. In other deployments, an IDSP may use third-party software, query authoritative sources, or request a managed verification result from an IDTP.

This document defines the method-provenance layer for those deployments. The goal is to make material method dependencies explicit, machine-readable, and policy-relevant without exposing raw evidence or weakening the IDSP's accountability to relying parties.

### 1.1. Relationship to Groundmark Attestations

The base `method_disclosure.executions` fields and types are defined in [I-D.noss-jeftovic-groundmark-attestation]. This document profiles those fields for IDSP/IDTP deployments and adds the managed Method Receipt rules. It does not define a second or incompatible execution-object shape. A Groundmark attestation remains the public object evaluated by a relying party. Private method receipts described here are evidence retained by the IDSP, or disclosed under a separate audit or dispute process, and are not public attestation payloads.

### 1.2. Non-Goals

This document does not:

- define claim types, claim-subject semantics, or attestation levels;
- define a central IDSP or IDTP registry;
- define constituency voting, certification governance, conflict-of-interest rules, or market-concentration policy;
- require public disclosure of raw verification evidence or personal data;
- transfer liability or relying-party accountability from the IDSP to an IDTP; or
- define a full audit protocol for disputes or regulator access.

### 1.3. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

## 2. Terminology

The terminology of the Groundmark core protocol [I-D.noss-jeftovic-groundmark-core] and the Groundmark attestation framework [I-D.noss-jeftovic-groundmark-attestation] applies. The following additional terms are used in this document.

**Identity Service Provider (IDSP)** - The issuer function that signs a Groundmark attestation and remains accountable to the relying party for that attestation.

**Identity Technology Provider (IDTP)** - A method-provider function that supplies verification technology, authoritative-data integration, or a managed verification result to an IDSP.

**Method Execution** - One concrete execution of a verification method contributing to an attestation.

**Method Receipt** - A private signed object produced by an IDTP for an `idtp-managed-service` method execution and retained by the IDSP.

**Receipt Digest** - A digest of a signed Method Receipt, carried in the public attestation so the IDSP can later prove which receipt supported issuance without publishing the receipt or raw evidence.

**Role-Scoped Authorization** - Relying-party trust policy that authorizes a party and key for a specific role and purpose, such as IDSP attestation signing, IDSP status signing, IDTP method receipts, or offline trust-bundle signing.

## 3. Functional Roles and Accountability

IDSP and IDTP are protocol and governance functions. A single organization MAY perform both functions, but each function is authorized, keyed, logged, and evaluated separately.

### 3.1. IDSP Function

The IDSP function:

1. accepts the operator relationship governed by the Groundmark attestation framework;
2. decides whether a claim should be issued;
3. signs the public Groundmark attestation;
4. signs status objects for the attestation using its purpose-separated status key; and
5. remains accountable to the relying party for the attestation's contents and method disclosure.

### 3.2. IDTP Function

The IDTP function supplies one or more method capabilities to an IDSP. Examples include:

- hosted verification workflow software;
- document or biometric checking technology;
- authoritative-source integration;
- risk scoring or screening technology; and
- managed verification in which the IDTP executes the method and returns a signed Method Receipt.

An IDTP does not become the attestation issuer merely because it provided technology or performed a method. A relying party MAY reject an attestation because a disclosed IDTP, method, key, version, jurisdiction, or execution mode is not authorized by policy.

### 3.3. Non-Delegable Issuer Accountability

The IDSP's accountability to the relying party is non-delegable. The IDSP may have contractual recourse against an IDTP, but the relying party is not required to pursue the IDTP to evaluate or dispute a Groundmark attestation.

An IDSP MUST NOT describe an attestation as policy-satisfying solely because an IDTP performed a method. The public attestation MUST still identify the IDSP issuer, the IDSP signing key, the claim, the method profile, and any material method dependencies needed for relying-party policy.

## 4. Method Execution Provenance

Every material verification method used for issuance SHOULD be represented as a Method Execution in `method_disclosure.executions`. A claim profile MAY define which executions are mandatory, optional, ordered, repeatable, or mutually exclusive.

### 4.1. Execution Modes

This document defines the following execution modes:

- **idsp-direct** - The IDSP performs the check using its own personnel, systems, and process.
- **idsp-operated-technology** - The IDSP performs the check using material third-party software, models, data, or hosted components, but the IDSP executes the method and controls the issuance decision.
- **idtp-managed-service** - An IDTP executes the method and returns a signed Method Receipt to the IDSP.
- **authoritative-source-query** - The IDSP directly controls a query to an authoritative source, with source class, source freshness, and source identity disclosed as required by the method profile. When an IDTP controls the query and returns a managed result, the execution mode is `idtp-managed-service` and the same source fields are populated.

Free-text method descriptions are supplementary only and MUST NOT be the sole policy input for a method execution.

### 4.2. Execution Object

A public Method Execution object appears inside `method_disclosure.executions` in a Groundmark attestation. It has the following fields:

- **method_id** (REQUIRED, string) - Immutable identifier of the method performed.
- **method_version** (REQUIRED, string) - Version of the method profile, technology, or integration.
- **execution_mode** (REQUIRED, string) - One of the execution modes in Section 4.1 or a registered extension.
- **performed_by** (REQUIRED, object) - The function that performed or controlled execution. See Section 4.3.
- **performed_at** (REQUIRED, string) - Completion time, formatted per [RFC3339].
- **valid_until** (OPTIONAL, string) - Time after which the method execution can no longer support new issuance without refresh, formatted per [RFC3339].
- **evidence_class** (OPTIONAL, array of strings) - Evidence categories examined, such as `domain-control`, `cryptographic-key-control`, `organization-record`, `government-issued-id`, or `biometric-liveness`.
- **source_class** (OPTIONAL, string) - Class of authoritative source queried, when applicable.
- **source_domain** (OPTIONAL, string) - Domain name of the authoritative source or material data provider, when disclosure is required by the method profile.
- **source_observed_at** (OPTIONAL, string) - Time at which source data was observed, formatted per [RFC3339].
- **provider** (OPTIONAL, object) - Material technology or service provider, when different from `performed_by`. The object contains `domain` (REQUIRED, DNS name) and optional `service` and `version` strings.
- **receipt_digest** (OPTIONAL, string) - Digest of the private signed Method Receipt. REQUIRED for `idtp-managed-service`.

Example:

```json
{
  "method_id": "organization-existence-check",
  "method_version": "1.0",
  "execution_mode": "idtp-managed-service",
  "performed_by": {
    "role": "idtp",
    "domain": "idtp.example",
    "key_id": "idtp-receipt-2026-01",
    "key_thumbprint": "vW3exampleY72kt7ydcH6r2P1mL0example"
  },
  "performed_at": "2026-07-21T16:00:00Z",
  "valid_until": "2026-08-20T16:00:00Z",
  "evidence_class": [
    "organization-record"
  ],
  "receipt_digest": "sha-256:tv-example-r12Y6DlPu1m6EfZ1Xexample"
}
```

### 4.3. Performer and Provider Semantics

The `performed_by` object has the following fields:

- **role** (REQUIRED, string) - `idsp`, `idtp`, or a registered extension.
- **domain** (REQUIRED, string) - DNSSEC-authenticated domain of the performer.
- **key_id** (OPTIONAL, string) - Key identifier for the role-specific key.
- **key_thumbprint** (OPTIONAL, string) - RFC 7638 thumbprint of the role-specific key.

`key_id` or `key_thumbprint` MUST identify a key actually used for, or authorized to vouch for, that method execution. An IDSP MUST NOT populate either field with the parent attestation-signing key merely because that key later signs the containing attestation.

For `idsp-operated-technology`, `performed_by.role` is `idsp`; a separate `provider` object identifies the material technology provider. This prevents an IDSP-operated vendor tool from being mistaken for a managed IDTP execution.

For `authoritative-source-query`, `performed_by` identifies the IDSP that controlled the query. The `source_class`, `source_domain`, and `source_observed_at` fields identify the source and freshness of the observed data as required by the method profile.

## 5. Private Signed Method Receipts

For `idtp-managed-service`, the IDTP issues a private signed Method Receipt to the requesting IDSP. The receipt is not part of the public attestation. It is retained by the IDSP and bound to the public attestation through `receipt_digest`.

### 5.1. Receipt Schema

A Method Receipt is a UTF-8 JSON [RFC8259] object constrained by I-JSON [RFC7493] and canonicalized using JCS [RFC8785]. The current schema is:

```json
{
  "schema_version": "1.0",
  "receipt_id": "urn:uuid:01910d3a-a232-7fa0-9d83-724196929111",
  "method_request_id": "mreq_9uo0xl4d9c6t8j2f",
  "requesting_idsp": "app.groundmark.id",
  "performing_idtp": "idtp.example",
  "performer_key_id": "idtp-receipt-2026-01",
  "method_id": "organization-existence-check",
  "method_version": "1.0",
  "claim_subject_digest": "sha-256:jF0exampleU2jP03PTbxn9ZF9example",
  "result_digest": "sha-256:g89exampleMEuGvmd3hjx6dRexample",
  "issuance_context": {
    "attestation_id": "urn:uuid:0190fbf6-07f0-7c1c-8a9c-2f35610297a1",
    "claim_type": "operator-verified",
    "intended_use": "groundmark-attestation-issuance"
  },
  "executed_at": "2026-07-21T16:00:00Z",
  "expires_at": "2026-08-20T16:00:00Z",
  "single_use": true,
  "signature": "MEUCIQ...base64url...=="
}
```

Fields:

- **schema_version** (REQUIRED, string) - Method Receipt schema version. The current value is `"1.0"`.
- **receipt_id** (REQUIRED, string) - Immutable globally unique identifier for this receipt.
- **method_request_id** (REQUIRED, string) - Unpredictable one-time request identifier generated by the IDSP.
- **requesting_idsp** (REQUIRED, string) - Domain of the requesting IDSP.
- **performing_idtp** (REQUIRED, string) - Domain of the performing IDTP.
- **performer_key_id** (REQUIRED, string) - IDTP purpose-specific method-receipt signing key identifier.
- **method_id** (REQUIRED, string) - Method identifier.
- **method_version** (REQUIRED, string) - Method version.
- **claim_subject_digest** (REQUIRED, string) - Digest of the claim subject or privacy-preserving issuance binding supplied by the IDSP.
- **result_digest** (REQUIRED, string) - Digest of the method result, not necessarily the raw result.
- **issuance_context** (REQUIRED, object) - Issuance transaction, intended use, or other binding context supplied by the IDSP.
- **executed_at** (REQUIRED, string) - Method execution time, formatted per [RFC3339].
- **expires_at** (REQUIRED, string) - Time after which the receipt can no longer support new issuance, formatted per [RFC3339].
- **single_use** (REQUIRED, boolean) - Whether the receipt is limited to one issuance context. This value MUST be true unless the method profile explicitly permits reuse.
- **signature** (REQUIRED, string) - Base64url-encoded [RFC4648] Ed25519 signature.

### 5.2. Receipt Signature and Canonicalization

The Method Receipt signature is computed over the JCS [RFC8785] canonical serialization of the strict parsed receipt object with the top-level `signature` field removed. Receipts MUST use UTF-8, reject duplicate object member names at every nesting level, and follow the I-JSON constraints in [RFC7493].

The IDTP's method-receipt public key MUST be published at `_agentid.<performing_idtp>` with a distinct `kid=` matching `performer_key_id` and `purpose=method-receipt-signing`, and it MUST be authenticated through DNSSEC under the core protocol. The IDSP MUST authorize the IDTP domain and selected key for that purpose. A relying party or auditor evaluating the receipt later MUST verify that the key was authorized for `method-receipt-signing` at the time of receipt issuance.

The public `receipt_digest` is SHA-256 over the complete JCS serialization of the signed Method Receipt, including its `signature`, encoded as `sha-256:<base64url>` without padding. The same strict parse tree used for signature verification MUST be used to produce this canonical form.

### 5.3. Replay and Single-Use Semantics

The IDSP MUST generate `method_request_id` unpredictably and MUST reject a receipt whose `method_request_id` does not match an outstanding method request. For single-use receipts, the IDSP MUST bind the receipt to one issuance context and MUST NOT reuse it to issue multiple independent attestations.

The IDSP MUST reject receipts that are expired, signed by an unauthorized IDTP key, bound to another IDSP, bound to another method, bound to another claim subject or result digest, or replayed outside the original issuance context.

### 5.4. IDSP Verification and Retention

Before relying on a Method Receipt, the IDSP MUST:

1. enforce strict JSON/I-JSON parsing and JCS signature verification;
2. verify the IDTP receipt signature;
3. verify role-scoped authorization for the IDTP domain, key, method, version, jurisdiction, and validity period;
4. verify `requesting_idsp`, `method_request_id`, method identifiers, digests, execution time, expiry, and issuance context;
5. store the receipt or an audit-grade encrypted representation of it;
6. compute the public `receipt_digest`; and
7. include only the required public provenance and receipt digest in the Groundmark attestation.

The IDSP MUST retain enough evidence to support audit, dispute handling, incident response, and reissuance decisions for the lifetime required by its trust framework or applicable law.

## 6. Public Attestation Disclosure

The public Groundmark attestation exposes method provenance, not raw personal evidence. For an `idtp-managed-service` execution, the attestation carries the IDTP identity, method identifier and version, execution mode, execution time, role-specific key identifier or thumbprint where policy requires it, evidence class, and `receipt_digest`.

Example `method_disclosure`:

```json
{
  "profile": "groundmark-operator-accountability",
  "profile_version": "1.0",
  "executions": [
    {
      "method_id": "dnssec-domain-challenge",
      "method_version": "1.0",
      "execution_mode": "idsp-direct",
      "performed_by": {
        "role": "idsp",
        "domain": "app.groundmark.id"
      },
      "performed_at": "2026-07-21T15:57:00Z",
      "evidence_class": [
        "domain-control"
      ]
    },
    {
      "method_id": "organization-existence-check",
      "method_version": "1.0",
      "execution_mode": "idtp-managed-service",
      "performed_by": {
        "role": "idtp",
        "domain": "idtp.example",
        "key_id": "idtp-receipt-2026-01"
      },
      "performed_at": "2026-07-21T16:00:00Z",
      "valid_until": "2026-08-20T16:00:00Z",
      "evidence_class": [
        "organization-record"
      ],
      "receipt_digest": "sha-256:tv-example-r12Y6DlPu1m6EfZ1Xexample"
    }
  ]
}
```

The public attestation MUST NOT include raw documents, biometrics, private identifiers, unredacted source responses, IDTP bearer URLs, or private receipt contents.

## 7. Role-Separated Keys and Trust Policy

A mixed organization that performs multiple Groundmark functions MUST use purpose-separated keys for:

- IDSP attestation signing;
- IDSP status signing;
- IDTP method-receipt signing; and
- offline trust-bundle signing, when applicable.

A key authorized for one purpose MUST NOT satisfy another purpose. For example, an IDTP method-receipt key MUST NOT satisfy an IDSP attestation-signing policy, and an attestation-signing key MUST NOT satisfy an offline trust-bundle signing policy.

Public IDSP and IDTP keys MUST use the purpose-scoped `_agentid` publication defined by the core protocol. IDSP attestation and status keys use `purpose=attestation-signing` and `purpose=status-signing`, respectively. IDTP Method Receipt keys use `purpose=method-receipt-signing`. Offline trust-bundle keys SHOULD be distributed through an independently pinned trust-root mechanism rather than the online `_agentid` RRset.

Trust policy MUST be role scoped. It SHOULD identify:

- authorized role (`idsp`, `idtp`, `trust-bundle-issuer`, or extension role);
- domain;
- key identifier or key thumbprint;
- purpose;
- claim types or method identifiers;
- allowed method versions;
- frameworks;
- jurisdictions;
- maximum attestation level, when applicable;
- validity window;
- minimum audit or practices-statement requirements; and
- emergency deny or suspension status.

The same organization MAY appear in multiple roles only when each role has an explicit authorization entry and purpose-specific key.

## 8. Dependency Indexing and Incident Propagation

An IDSP that issues attestations using material method dependencies MUST index every issued attestation by:

- claim type;
- attestation ID;
- method profile and version;
- method execution ID or receipt digest, where available;
- provider or IDTP domain;
- provider or IDTP key identifier and thumbprint, where available;
- execution mode;
- authoritative source class and source domain, where applicable;
- issuance time and status sequence; and
- affected status object URL.

If an IDTP, provider, method key, method version, authoritative source integration, or receipt-signing key is suspended, compromised, found vulnerable, or no longer authorized, the IDSP MUST:

1. stop new issuance using the dependency;
2. identify all dependent attestations;
3. determine whether the dependency failure requires suspension, revocation, supersession, or re-verification according to the method profile and trust framework;
4. publish refreshed signed status objects for affected attestations;
5. queue re-verification or reissuance where appropriate; and
6. preserve audit evidence for the incident decision.

These actions MUST preserve the attestation status lifecycle in [I-D.noss-jeftovic-groundmark-attestation]. Suspension is reversible when re-verification resolves the incident. Revocation is terminal for an `attestation_id`; any later acceptable assertion requires a newly issued attestation with a new identifier. Refreshing a status object increments its sequence but MUST NOT change a terminal state.

A relying party MAY reject otherwise valid attestations when a disclosed method dependency, IDTP, method version, or key is unauthorized, suspended, vulnerable, expired, or outside jurisdictional policy.

## 9. Security and Privacy Considerations

Method provenance adds supply-chain visibility, but it also creates new privacy and correlation risks. Implementations MUST minimize public disclosure and SHOULD prefer digests, coarse evidence classes, and method identifiers over raw evidence.

Public attestations MUST NOT expose raw personal evidence, private method receipts, personal identifiers not required by the claim, private source responses, or bearer URLs. IDSPs and IDTPs MUST NOT log raw tokens or unnecessary evidence in ordinary request logs.

Receipt digests are linkable if reused. IDSPs MUST NOT reuse single-use Method Receipts across unrelated attestations. Where a method profile permits receipt reuse, it MUST define the linkability and retention consequences.

An IDTP receipt signature proves that the IDTP signed the receipt. It does not prove that the IDSP was authorized to issue the final attestation, that the relying party trusts the IDTP, or that the disclosed method satisfies the relying party's policy. Role-scoped authorization remains required.

Governance concerns such as voting rights, certification criteria, conflicts of interest, and market concentration are important but separate. They belong in a governance document or trust-framework policy, not in this protocol profile.

## 10. IANA Considerations

This document makes no IANA requests.

Future documents may request registration of method execution modes, performer roles, key purposes, evidence classes, or method-receipt schema versions.

## 11. References

### 11.1. Normative References

- **[I-D.noss-jeftovic-groundmark-attestation]** - Noss, E. and M. Jeftovic, "Groundmark Attestation Framework and Identity Service Provider Profile", Work in Progress, Internet-Draft, draft-noss-jeftovic-groundmark-attestation-01, 2026, <https://datatracker.ietf.org/doc/html/draft-noss-jeftovic-groundmark-attestation-01>.
- **[I-D.noss-jeftovic-groundmark-core]** - Noss, E. and M. Jeftovic, "DNS-Anchored Identity Discovery for Autonomous Agents", Work in Progress, Internet-Draft, draft-noss-jeftovic-groundmark-core-01, 2026, <https://datatracker.ietf.org/doc/html/draft-noss-jeftovic-groundmark-core-01>.
- **[RFC2119]** - Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997, <https://www.rfc-editor.org/rfc/rfc2119>.
- **[RFC3339]** - Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339, July 2002, <https://www.rfc-editor.org/rfc/rfc3339>.
- **[RFC4648]** - Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006, <https://www.rfc-editor.org/rfc/rfc4648>.
- **[RFC7493]** - Bray, T., Ed., "The I-JSON Message Format", RFC 7493, March 2015, <https://www.rfc-editor.org/rfc/rfc7493>.
- **[RFC7638]** - Jones, M. and N. Sakimura, "JSON Web Key (JWK) Thumbprint", RFC 7638, September 2015, <https://www.rfc-editor.org/rfc/rfc7638>.
- **[RFC8032]** - Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017, <https://www.rfc-editor.org/rfc/rfc8032>.
- **[RFC8174]** - Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017, <https://www.rfc-editor.org/rfc/rfc8174>.
- **[RFC8259]** - Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017, <https://www.rfc-editor.org/rfc/rfc8259>.
- **[RFC8785]** - Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020, <https://www.rfc-editor.org/rfc/rfc8785>.

### 11.2. Informative References

None.

## Acknowledgements

The authors thank the Groundmark reviewers who separated issuer accountability, technology provision, and governance policy into distinct protocol concerns.

## Change Log

### -00

- Initial focused method-provenance profile for IDSP and IDTP functions.
- Defined execution modes, public method execution records, private signed method receipts, role-separated keys, role-scoped trust policy, dependency incident propagation, and privacy boundaries.
- Aligned the execution-object shape with the attestation draft, defined the provider object and receipt digest precisely, and clarified purpose-scoped DNS key publication.
- Clarified authoritative-source execution, method-key attribution, and terminal-revocation behavior during dependency incidents.

## Authors' Addresses

**Elliot Noss**
Groundmark
Email: elliot@noss.org
URI: https://groundmark.org

**Mark Jeftovic**
easyDNS Technologies Inc.
Email: markjr@easydns.com
