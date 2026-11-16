# Groundmark Protocol

**DNS-anchored identity and IDSP-served credentials for autonomous agents**

| | |
|---|---|
| Version | Draft for review, 16 November 2026 |
| Editors | Elliot Noss (Groundmark), Mark Jeftovic (easyDNS) |
| Basis | Groundmark Translation Map v1.0, 16 November 2026, with Elliot's D12 ruling of the same day |
| Replaces | The unsubmitted working texts now in `archive/` and, on submission of the IETF -01, `draft-noss-jeftovic-groundmark-core-00` and `draft-noss-jeftovic-groundmark-attestation-00` |
| Status | Not yet reviewed by Mark. Items marked **Open** are not decided. Items marked `TODO(verify)` cite something not yet checked against its source. |

This is the complete protocol text. The IETF Internet-Draft `draft-noss-jeftovic-groundmark-core-01` is a deliberately shorter document drawn from it; where the two differ, this document is the fuller statement and the -01 is the submitted record.

---

## Contents

1. Introduction
2. The Privacy Argument
3. Level 0: the Open On-Ramp
4. The DNS Anchor
5. Request Authentication
6. Presentation by Reference
7. The IDSP Retrieval Protocol
8. The Credential
9. Method Disclosure
10. IDSP Keys and `did:web`
11. Verification
12. Status and Revocation
13. The IDSP Role
14. Claim Types
15. Accreditation and Trust Frameworks
16. Key Rotation and Identity Reset
17. Security Considerations
18. Migration and the Legacy Window
19. Open Issues
20. Related Work
21. References
- Appendix A. Failure Codes (informative)
- Appendix B. Informative Mapping to IETF SD-JWT VC
- Appendix C. Disposition of the Earlier Texts
- Appendix D. Items to Verify

---

## 1. Introduction

Autonomous agents now transact on the Internet for organizations and for people. A counterparty receiving a request from an agent has two questions. Which key is this agent currently authorized to sign with? And, when the transaction warrants it, who stands behind the agent, and how does anyone know?

Groundmark answers the first with DNS and the second with an accountable third party. The operator's DNSSEC-signed zone publishes the agent's request-signing key and names the agent's Identity Service Provider (IDSP). The agent signs its requests with HTTP Message Signatures [RFC9421]. When the relying party needs more than a verified key, it fetches a credential about the agent from the IDSP that DNS names, using a reference the agent carried in its signed request.

Groundmark is a profile of existing standards wherever one exists. The credential is a W3C Verifiable Credential [VCDM2] secured as an SD-JWT [VC-JOSE-COSE] [RFC9901]. The IDSP is identified by `did:web` [DID-WEB]. Status is a Token Status List [TOKEN-STATUS-LIST]. Accreditation is queried with TRQP [TRQP]. What Groundmark itself specifies is small, and it is listed in Section 1.2.

### 1.1. The Flow

1. **DNS says who the agent's IDSP is.** The operator publishes the agent's key in an `_agentid` record and, if it uses an IDSP, one `_idsp` record naming the IDSP and nothing else. Both are in a DNSSEC-signed zone.
2. **The agent's signed request carries a reference.** The agent adds a `Groundmark-Claim` header carrying an opaque reference at its IDSP and covers that header with its RFC 9421 signature.
3. **The relying party checks that the reference points at that IDSP.** After verifying the request signature against the DNSSEC-validated `_agentid` key, it checks that the reference's host is an IDSP named in the agent's DNSSEC-validated `_idsp` records. It fetches nothing that fails this check.
4. **The relying party fetches the credential from the IDSP directly.** The IDSP serves a credential it signed, containing only the claims released to that relying party, with structured evidence of how each claim was verified.
5. **The relying party verifies the credential and binds it to the request.** The credential's issuer is the IDSP named in DNS, its subject is the agent domain being evaluated, and its `cnf` key is the exact key that verified the request.

Two things stay in DNS: the agent's key and the name of its IDSP. Everything about any claim leaves DNS. An agent with a key in `_agentid` and no IDSP at all is a complete Groundmark participant at Level 0 (Section 3).

### 1.2. What Groundmark Specifies

Three core elements:

| Core element | What this document requires | Nearest precedent |
|---|---|---|
| IDSP-served presentation by reference | The agent carries a reference, not a credential. The relying party dereferences it at the IDSP and receives an IDSP-signed credential with only the claims released to that relying party. (Sections 6, 7) | ISO/IEC 18013-5 §3.16 and §3.17 (server retrieval and its token) [ISO18013-5]; OpenID Federation 1.0 §8.1 (fetch endpoint) [OIDF] |
| Mandatory issuer method disclosure | Every credential carries structured evidence of how its claim was verified. The requirement is normative. (Section 9) | VCDM 2.0 §5.6 `evidence` [VCDM2]: the slot exists; no standard requires it be filled |
| DNSSEC-anchored pointer to an accredited IDSP | The operator's zone names its IDSP under DNSSEC. Relying parties must validate. Accreditation is checked against anchors the relying party trusts. (Sections 4.2, 15) | draft-latour-dns-and-digital-trust-02 (`_trustregistry`, expired) [LATOUR]; draft-ranjbar-dane-did (DNSSEC mandatory) [RANJBAR] |

Supporting residue, also specified here:

- the release rule and the IDSP's disclosure record (Section 7.4, 7.5);
- issuer and IDSP as separable roles, with the IDSP accountable for what it serves (Section 13);
- bounded predicates about operators and about humans behind them (Section 14);
- RFC 9421 request signing, kept as shipped (Section 5);
- the four bindings between request, DNS and credential (Section 11.1);
- two status rules that Token Status List leaves to the verifier (Section 12.3);
- reference hygiene and fetch hardening (Sections 6.3, 7.7);
- self-issuance (Section 4.4).

### 1.3. What Groundmark Adopts

| Concern | Adopted specification |
|---|---|
| Credential data model | W3C VC Data Model 2.0 [VCDM2], with type-specific processing |
| Securing format, mandatory | SD-JWT [RFC9901] as profiled by VC-JOSE-COSE §3.2 [VC-JOSE-COSE] |
| Securing format, optional extra | Data Integrity `eddsa-jcs-2022` [VC-DI-EDDSA]; `ecdsa-jcs-2019` [VC-DI-ECDSA] for ES256 IDSPs |
| IDSP identifier and key document | `did:web` [DID-WEB]; Controlled Identifiers 1.0 [CID] |
| Holder binding | `cnf` [RFC7800], thumbprint form `jkt` [RFC9449] over an RFC 7638 thumbprint [RFC7638] |
| Status | Token Status List, draft -21 [TOKEN-STATUS-LIST] |
| Accreditation query | TRQP v2.0 §6 [TRQP]; governance on the ToIP Governance Metamodel [TOIP-GMM] with the vLEI EGF v4.0 [VLEI-EGF] as template |
| Request signing | HTTP Message Signatures [RFC9421] and Digest Fields [RFC9530], compatible with Web Bot Auth [WEBBOTAUTH] |
| Evidence type registration | VC Extensions §2.3 [VC-EXTENSIONS] |

### 1.4. Non-Goals

This document does not:

- define legal identity or require any personal attribution. Anonymous and pseudonymous operation at Level 0 is a first-class mode;
- define a trust framework, an accreditation body, or the meaning of attestation levels. Those belong to trust frameworks (Section 15);
- define a new DID method or a new cryptographic primitive;
- replace OAuth, OpenID, AAuth, MCP, x402 or any other identity, authorization or payment protocol. Groundmark composes with them.

### 1.5. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

### 1.6. Terminology

**Operator.** The person or organization that deploys and controls an agent and is accountable for it.

**Agent.** An autonomous software instance acting for an operator. Its identity anchor is the agent domain.

**Agent domain.** The FQDN at which the agent's `_agentid` and `_idsp` records are published, usually a subdomain of the operator's registered domain. All comparisons use the lowercase IDNA A-label form with no trailing root label. The semantics of the domain string carry no protocol weight.

**Key custodian.** The party that operates the agent's private key: the operator, the agent runtime, or a hosting provider.

**Agent key thumbprint.** The RFC 7638 [RFC7638] SHA-256 JWK thumbprint of the agent request-signing key selected for a request, Base64url-encoded without padding [RFC4648].

**Agent identity instance.** The pair `(agent domain, agent key thumbprint)`. This, not the FQDN alone, is the identity used for decisions that depend on continuity (Section 16.2).

**Identity Service Provider (IDSP).** The party named in an agent's `_idsp` record that serves credentials about the agent and its operator, signs them or serves them on behalf of their issuer, discloses its methods, publishes their status, and is accountable to relying parties for what it serves. IDSP is the protocol role. An IDSP is identified by its domain, which is also its `did:web` identifier.

**Issuer.** The party whose signature secures a credential. In this version the issuer and the IDSP are the same party (Section 13.3).

**Identity Technology Provider (IDTP).** A party that supplies a verification method to an IDSP: technology, an authoritative-source integration, or a managed service. An IDTP is accountable to the IDSPs that use it, not to relying parties.

**Relying party.** The service that receives an agent's request and decides whether to act on it.

**Reference.** The opaque HTTPS URL at an IDSP that an agent carries in `Groundmark-Claim` and a relying party dereferences to obtain a credential.

**Release rule.** The operator's instruction to its IDSP about which claims may be released to which relying parties, and under what consent.

**Disclosure record.** The IDSP's record of each release: which credential, about which operator, to which relying party, when, under what consent.

**Credential.** A Verifiable Credential [VCDM2], secured as specified in Section 8, that an IDSP serves about an agent and its operator.

**Self-issuance.** The case where an operator's `_idsp` record names the operator's own domain (Section 4.4).

**Terminology note: "attestation".** Earlier Groundmark texts call the IDSP's signed statement an "attestation". In this document that statement is a credential. In the vocabulary of the RATS architecture [RFC9334] and the Entity Attestation Token [RFC9711], a Groundmark credential is not Evidence about a device's state; if a RATS term is wanted, it is closest to an attestation result. Where this document says "attestation" it means a Groundmark credential, and the word appears mainly in role names and in "attestation level".

---

## 2. The Privacy Argument

This section is the design's central argument. Every other choice in the protocol follows from it.

### 2.1. What DNS Discloses, and What It No Longer Does

DNS is public, cached, logged by passive collectors and queried in the clear across many paths. Anything placed there is published to everyone, permanently in practice. The earlier Groundmark design put claim references in DNS: in their open form a claim type, an issuer and a URL that anyone could follow; in their committed form a digest that still revealed how many credentials an agent held and when each changed.

This design publishes two things:

- the agent's public request-signing key, in `_agentid`;
- the domain of the agent's IDSP, in `_idsp`.

Nothing in DNS states what kind of claim an agent can back, how many, from whom beyond the IDSP's name, when they were issued, or where they can be read. A reader of DNS learns that the agent participates in Groundmark and which IDSP vouches for it. That is the same order of disclosure as an MX record naming a mail provider.

### 2.2. Claims Pass Between the Relying Party and the IDSP

A claim reaches a relying party only when the agent presents a reference in a signed request, and only by a fetch from the IDSP that DNS names. The IDSP applies the operator's release rule and serves only the claims released to that relying party (Section 7.4). The decision to disclose is made per request by the agent and per relying party by the IDSP, both under the operator's control. This is minimal disclosure in Kim Cameron's sense [Cameron2005]: each credential is a bounded predicate, not a dossier, and it is disclosed to the party that needs it, not published.

### 2.3. The Deliberate Trade: No Pre-Contact Evaluation

A relying party can no longer read an agent's claims from DNS before first contact. It cannot pre-screen counterparties on their claims, and third-party monitors cannot catalogue what agents hold. This is a cost, and it is accepted on purpose: the only way to support pre-contact evaluation is to publish claims, and publishing claims is the disclosure this design removes.

The answer is `Groundmark-Accept` (Section 6.2). A relying party states what it accepts, the agent presents what its operator permits, and the cost is at most one round trip. Because the agent is never obliged to present what a relying party lists, the advertisement cannot be used to probe for what an agent holds.

### 2.4. What Remains Observable

The design does not make agents unobservable, and it does not claim to.

- **Linkability by agent domain.** Every relying party sees the agent domain, and relying parties can correlate on it. An agent domain is globally unique by construction. Operators that need unlinkability across relying parties SHOULD use per-relationship agent domains, at the cost of issuing and verifying more credentials.
- **The IDSP sees where its credentials go.** Because relying parties fetch from the IDSP, the IDSP learns which relying parties an agent presents to, and when. This is the same property as server retrieval in ISO/IEC 18013-5 [ISO18013-5]. For organizational agents it is the accountability the IDSP exists to provide, and the disclosure record (Section 7.5) makes it explicit. For a person's agent it means the choice of IDSP is a choice of who sees the agent's counterparties. A person MAY self-issue (Section 4.4) or choose an IDSP whose practices on this are acceptable to them. A trust framework SHOULD require accredited IDSPs to state how they use and retain disclosure records.
- **Resolver-side observation.** Lookups of `_agentid` and `_idsp` are visible to network observers on the resolution path, as any DNS lookup is. Relying parties concerned about this SHOULD use an encrypted transport to their recursive resolver [RFC8484].
- **The IDSP name is a signal.** An `_idsp` record naming an IDSP known for one kind of verification discloses something by itself. Operators choosing a specialist IDSP accept that.

### 2.5. Organizational and Personal Defaults

Organizational agent identity has different privacy defaults from human identity. An organization's domain already publishes MX, SPF, DKIM and CAA records; adding a key and a provider name extends that disclosure only slightly. A person's agent is different, which is why the protocol makes no claim public at all and leaves every release to the person's release rule. A person who prefers not to publish records under a personal domain SHOULD use an agent domain under a provider's domain, where the provider's relationship with the person preserves the accountability chain.

### 2.6. Registrant Disclosure

Registrant disclosure through RDAP, where an operator voluntarily publishes structured registrant facts, is not part of this protocol. An IDSP MAY use registrant disclosure as an evidence source for a method, recorded in `evidence` like any other source (Section 9). Nothing in this protocol extracts or cross-references registrant data that the operator has not chosen to disclose.

---

## 3. Level 0: the Open On-Ramp

An agent that signs its requests with a key published in a DNSSEC-validated `_agentid` record, and has no `_idsp` record, is a complete Groundmark participant. No IDSP, credential, registration or payment is required.

A relying party that implements only Sections 4.1, 4.3 and 5 can verify that a request was signed by the private key corresponding to the key currently published for the agent domain under DNSSEC. It can conclude nothing about the operator's identity, legal standing, location, compliance, brand authorization, or continuity across a key change. A Level 0 result MUST NOT be described as legal identity, brand verification or operator accountability.

Level 0 is expected to cover most agent transactions. Everything after Section 5 is the optional path a relying party takes when its risk calls for more. The principle is to authenticate the minimum necessary for the risk of the transaction.

---

## 4. The DNS Anchor

All Groundmark records are TXT records under underscored labels [RFC8552], carry the version tag `v=gm1` first, and MUST be published in a DNSSEC-signed zone.

### 4.1. The `_agentid` Record

The `_agentid` record publishes a public key with a declared purpose. At an agent domain it publishes the agent's request-signing key. At an IDSP domain it publishes the IDSP's credential-signing and status-signing keys (Section 10).

```dns
_agentid.purchasing.acmecorp.example. 300 IN TXT
  "v=gm1; k=ed25519; purpose=request-signing; kid=k1; p=<base64url-public-key>"
```

#### 4.1.1. Grammar

```abnf
agentid-record  = version 1*( ";" SP agentid-param )
version         = "v=gm1"
agentid-param   = key-alg-param / pubkey-param / keyid-param /
                  purpose-param / ext-param
key-alg-param   = "k=" key-alg
key-alg         = "ed25519" / p256-alg / x-token
p256-alg        = "p256"   ; Open: value and encoding, Section 19.2
pubkey-param    = "p=" base64url-value
keyid-param     = "kid=" 1*( ALPHA / DIGIT / "-" / "_" / "." )
purpose-param   = "purpose=" key-purpose
key-purpose     = 1*( ALPHA / DIGIT / "-" )
ext-param       = param-name "=" param-value
param-name      = 1*( ALPHA / DIGIT / "-" )
param-value     = *( %x21-3A / %x3C-7E )
                  ; printable ASCII excluding ";"
base64url-value = 1*( ALPHA / DIGIT / "-" / "_" )
x-token         = "x-" 1*( ALPHA / DIGIT / "-" )
```

#### 4.1.2. Processing

- `k=` and `p=` MUST be present. For `ed25519`, `p=` is the Base64url encoding without padding [RFC4648] of the raw 32-byte public key [RFC8032].
- **Open (Section 19.2):** the `k=` value and the `p=` encoding for a P-256 key. The `p256` token in the grammar is a placeholder.
- `purpose=` values defined here: `request-signing` (agent domains), `attestation-signing` and `status-signing` (IDSP domains). An omitted `purpose=` means `request-signing` and MUST NOT authorize any other use. A key MUST be used only for its declared purpose. A record with an unrecognized purpose MUST NOT be used.
- A single record MAY omit `kid=`. When more than one record is present at the label, every record MUST carry a `kid=` and every `kid=` MUST be distinct; otherwise the relying party MUST treat the RRset as invalid and MUST NOT verify against any record in it.
- Operators SHOULD set the TTL to 300 seconds or less. Relying parties MUST NOT cache a record beyond its TTL.

### 4.2. The `_idsp` Record

The `_idsp` record names an IDSP for the agent. It carries the IDSP's domain and nothing else: no claim type, URL, digest or expiry.

```dns
_idsp.purchasing.acmecorp.example. 300 IN TXT
  "v=gm1; idsp=verify.example.net"
```

#### 4.2.1. Grammar

```abnf
idsp-record  = version ";" SP "idsp=" idsp-domain *( ";" SP ext-param )
idsp-domain  = label *( "." label )
label        = ( ALPHA / DIGIT ) *( *"-" ( ALPHA / DIGIT ) )
```

`version` and `ext-param` are as in Section 4.1.1.

#### 4.2.2. Processing

- One record per IDSP. An agent MAY have several `_idsp` records, one for each IDSP it uses. Each names one IDSP.
- `idsp=` is a DNS name in lowercase A-label form with no trailing dot, no port and no path. It is the host the IDSP serves references from, the domain of its `did:web` identifier, and the domain at which it publishes `_agentid` keys (Section 10).
- Publishers MUST NOT add parameters that describe claims. Receivers MUST ignore unknown parameters.
- A relying party MUST retrieve `_idsp` with the resolver profile of Section 4.3. Secure NODATA means the agent names no IDSP; the agent is Level 0. Any validation failure MUST be observable and MUST NOT be treated as ordinary absence when policy requires a credential.
- Removing an `_idsp` record withdraws that IDSP's standing for the agent. After cached copies expire, references at that IDSP fail the host check (Section 6.1.3). Withdrawal is not revocation and does not change any credential's status.
- An operator changes IDSP by changing this record. That is the whole of the DNS change.

### 4.3. DNSSEC and the Resolver Profile

All Groundmark DNS lookups MUST be validated under DNSSEC [RFC4033]. A key or IDSP name from an unsigned or unvalidated zone MUST NOT be used.

An implementation MUST use one of:

- in-process DNSSEC validation; or
- a trusted validating resolver reached over a channel that provides endpoint authentication and integrity. Loopback or protected local IPC is acceptable. An AD bit received over an untrusted network path MUST NOT be relied on.

`insecure`, `bogus`, `indeterminate`, timeout, transport failure, and any other inability to confirm a validated answer are fatal for `_agentid` lookups and for `_idsp` lookups made because policy requires a credential. Secure NODATA MUST be distinguishable from validation failure in diagnostics.

No open-source DID resolver or agent-key resolver validates DNSSEC today. This requirement is Groundmark's own; it applies to the operators, IDSPs and relying parties that choose to participate, not to the Internet at large.

### 4.4. Self-Issuance

An operator MAY publish an `_idsp` record naming its own domain and serve credentials about itself by exactly the protocol any IDSP uses: a `did:web` document, purpose-separated keys, method disclosure, status. Nothing in the protocol prevents this and nothing in the protocol vouches for it. The credential states truthfully who issued it and by what method. An accreditation query for a self-issuing operator returns that it is not accredited. The relying party decides what the credential is worth.

Self-issuance replaces the self-asserted DNS claim of earlier texts. It is also the way in for a person running their own agent.

### 4.5. Retired: `_agentclaim`

The `_agentclaim` record, in its open, committed and self-asserted forms, is retired. Conforming publishers MUST NOT publish new `_agentclaim` records. A verifier MAY read existing records only under an explicit legacy policy during the legacy window (Section 18).

---

## 5. Request Authentication

Groundmark profiles HTTP Message Signatures [RFC9421]. The signature base, `Signature-Input` and `Signature` fields are as RFC 9421 defines them. This section fixes the choices RFC 9421 leaves to applications; RFC 9421 §1.4 leaves key retrieval to the application, and Groundmark's is DNS. This section is unchanged in substance from the shipped protocol.

### 5.1. Algorithms

- Agents MUST support Ed25519 [RFC8032], identified as `ed25519` in the HTTP Signature Algorithms registry [RFC9421].
- Agents MAY use ECDSA P-256, identified as `ecdsa-p256-sha256` [RFC9421], once its `_agentid` encoding is settled (Section 19.2).
- Relying parties MUST support both.

### 5.2. Key Identification

The `keyid` parameter MUST be either:

- the agent domain, lowercase, with no `#` suffix. The relying party retrieves `_agentid` at that domain and proceeds only if exactly one usable `request-signing` record is present and it has no `kid=`; or
- the agent domain followed by `#` and a key identifier, for example `purchasing.acmecorp.example#k2`. The relying party selects the record whose `kid=` matches and whose purpose is `request-signing` or omitted. This form MUST be used when more than one `_agentid` record is published.

A signature whose `keyid` does not resolve to exactly one usable record MUST be rejected.

### 5.3. Covered Components

A signature MUST cover `@method`, `@authority` and `@target-uri` (RFC 9421 §2.2). A request with a body MUST carry and cover `content-digest` [RFC9530], with `sha-256` mandatory to implement. A request carrying `Groundmark-Claim` MUST cover `groundmark-claim`. Every request field the relying party uses for authorization, tenant or resource selection, routing, amounts, claim selection, idempotency or any durable side effect MUST be covered.

### 5.4. Signature Parameters

`Signature-Input` MUST include `created`, `keyid` and `alg` (RFC 9421 §2.3). `alg` is required by this profile and MUST match the key's algorithm. It SHOULD include `expires`, no more than 300 seconds after `created`. Relying parties MUST reject a `created` more than 300 seconds from their clock in either direction and an `expires` in the past.

### 5.5. Request Profiles and Nonces

**Read-only profile.** For safe, idempotent retrieval with no financial, authorization or durable effect. The rules of Sections 5.3 and 5.4 apply; a relying party MAY require a nonce by local policy.

**State-changing profile.** For any operation with financial, authorization or durable effect, whatever the HTTP method:

- the relying party MUST issue an unpredictable nonce with a lifetime of at most 300 seconds. It SHOULD deliver the nonce as the `nonce` parameter of an `Accept-Signature` field (RFC 9421 §5.1) in the response that challenges or precedes the request, listing the components it expects covered, including `groundmark-claim` when it expects a credential. An application MAY deliver the nonce another way;
- the nonce MUST be carried as a signature parameter and is therefore covered through `@signature-params`;
- `expires` MUST be present;
- the nonce MUST be consumed with one atomic consume-if-absent operation, and only at the final acceptance boundary: after request verification for a Level 0 decision, or after every credential, status and policy check for a decision that uses a credential. A request that fails any check leaves the nonce unconsumed. A nonce reported as already consumed MUST cause rejection as a replay.

RFC 9421 §7.2.2 discusses nonce-based replay protection.

### 5.6. Verification Steps

1. Parse `Signature-Input` and `Signature` [RFC9421]; confirm the required components and parameters.
2. Check `created` and `expires`.
3. Resolve the agent domain from `keyid` and retrieve `_agentid` under Section 4.3; select the key under Section 5.2.
4. If there is a body, verify `content-digest`.
5. Reconstruct the signature base and verify the signature with the selected key.
6. Compute the agent key thumbprint. The result is the agent identity instance.
7. If policy requires a credential, continue with Section 11.
8. Consume the nonce at the final acceptance boundary (Section 5.5).

### 5.7. Web Bot Auth Compatibility

Groundmark request signatures are intended to be acceptable to relying parties that implement Web Bot Auth [WEBBOTAUTH]. An agent MAY additionally carry the Web Bot Auth fields in the same request. `TODO(verify)`: the exact Groundmark `tag` value and how a Groundmark `keyid` relates to the `Signature-Agent` field, against draft-ietf-webbotauth-httpsig-protocol-01. This compatibility is optional and adds nothing a Groundmark verifier depends on.

---

## 6. Presentation by Reference

### 6.1. The `Groundmark-Claim` Header Field

An agent presents a claim by carrying a `Groundmark-Claim` header field and covering it with its request signature. The header binds one reference to one request, so it cannot be stripped, substituted or replayed against another request. Because no claim is in DNS, presentation is the only way a relying party learns of a claim.

#### 6.1.1. Syntax

```abnf
groundmark-claim  = claim-member *( ";" SP claim-member )
claim-member      = claim-type-member / ref-member /
                    idsp-member / ext-member
claim-type-member = "claim-type=" DQUOTE claim-type DQUOTE
ref-member        = "ref=" DQUOTE quoted-url DQUOTE
idsp-member       = "idsp=" DQUOTE idsp-domain DQUOTE
ext-member        = param-name "=" DQUOTE quoted-value DQUOTE
claim-type        = short-type / type-uri
short-type        = ALPHA *( ALPHA / DIGIT / "-" )
type-uri          = "https://" 1*( %x21 / %x23-3A / %x3C-7E )
quoted-url        = "https://" 1*( %x21 / %x23-3A / %x3C-7E )
                    ; visible ASCII excluding DQUOTE and ";"
quoted-value      = *( %x21 / %x23-3A / %x3C-7E )
```

`idsp-domain`, `param-name` are as in Section 4. `claim-type` names a claim type as defined in Section 14.

`claim-type` and `ref` MUST be present. `idsp` is OPTIONAL; when present it MUST equal the host of `ref`. Unknown members MUST be ignored.

```http
Groundmark-Claim: claim-type="operator-verified";
  ref="https://verify.example.net/r/Vb2m7kQ1xZr9Lw0pT4yHcA"
```

This version permits one `Groundmark-Claim` field per request; a request with more than one MUST be rejected. **Open (Section 19.1):** under this design every claim reaches the relying party by presentation, so a one-reference limit blocks any policy that needs two claims together. The bundle design is waiting on Mark.

#### 6.1.2. Signature Coverage

A request carrying `Groundmark-Claim` MUST cover `groundmark-claim`. A relying party MUST reject a request whose `Groundmark-Claim` is present but not covered.

#### 6.1.3. The Host Check, Before Any Fetch

After the request signature verifies and before anything is fetched, the relying party MUST:

1. retrieve `_idsp` for the agent domain under Section 4.3;
2. parse `ref` as an HTTPS URL and extract its host, lowercased in A-label form; and
3. confirm that the host is exactly equal to the `idsp=` value of one of the DNSSEC-validated `_idsp` records.

If the RRset fails validation, if there is no `_idsp` record, or if the host matches none, the relying party MUST reject the presented claim and MUST NOT fetch `ref`. This check is what makes every fetched URL one the operator's DNSSEC-signed zone authorized, and what makes a reference useless once the operator moves to another IDSP. It replaces the earlier `endpoint_url` binding: a credential re-hosted elsewhere fails here.

#### 6.1.4. The Presented Claim Satisfies Policy

The presented claim MUST be the one that satisfies the relying party's policy. A relying party MUST NOT accept a request on the strength of a different credential when its policy required the presented claim type.

### 6.2. The `Groundmark-Accept` Header Field

A relying party states which claim types can satisfy its policy at a resource by sending `Groundmark-Accept` in a response. It divides the work with `Accept-Signature`: `Accept-Signature` says how to sign; `Groundmark-Accept` says what to present.

#### 6.2.1. Syntax

`Groundmark-Accept` is a List Structured Field [RFC9651]. Each member is a Token naming a short claim type or a String carrying a claim type URI (Section 14.1), with these OPTIONAL parameters:

- `level`: an Integer from 0 to 3, the minimum attestation level, as defined by the trust framework the relying party applies (Section 15.2). Absent means any level.
- `idsp`: a String carrying an IDSP domain the relying party accepts for this claim type. A claim type accepted from several IDSPs is listed once per IDSP. Absent means the relying party does not disclose its issuer policy here.

```http
Groundmark-Accept: operator-verified;level=1,
  age-over-18;idsp="verify.example.net"
```

A receiver MUST ignore members and parameters it does not recognize. A field that fails to parse MUST be treated as absent.

#### 6.2.2. Semantics

The field states that the relying party implements this document for the resource and that a credential of each listed type, within the stated constraints, can contribute to satisfying its policy. It does not say whether listed types are alternatives or all required.

A relying party MUST include `Groundmark-Accept` in any 401 or 403 that rejects a request for lack of an acceptable credential. It SHOULD include it in 402 responses, so payment and identity requirements are learned in one round trip. It MAY send it on any response. When it accompanies a challenge, the response SHOULD carry `Accept-Signature` listing `groundmark-claim`, with a `nonce` when the state-changing profile applies. A relying party that implements only Level 0 does not send it.

An advertisement is not a commitment. The relying party MUST enforce its policy on the signed request whatever it advertised.

#### 6.2.3. Agent Processing

`Groundmark-Accept` is advisory. An agent MUST apply its operator's disclosure policy for the target authority before presenting anything, and MUST NOT present a claim solely because its type was listed. Within what that policy permits, the agent SHOULD present the least disclosing claim that matches. An agent with nothing it may present proceeds at Level 0 and lets the relying party decide. This agent-side policy is the operator-side half of the release rule (Section 7.4).

#### 6.2.4. Integrity and Caching

The field is protected by TLS and is not otherwise signed unless the relying party signs its responses under RFC 9421. A stripped field leaves the agent at Level 0. The field describes the resource's policy, not the requester, and MAY appear on cacheable responses without a `Vary` entry.

For wallet ecosystems, a `Groundmark-Accept` field maps informatively onto an OpenID4VP 1.0 DCQL query (§6) [OID4VP]. `TODO(verify)`: write out the mapping against OpenID4VP 1.0 §6 before citing it beyond this sentence.

### 6.3. Reference Hygiene

A reference is a bearer value. Holding it is what allows a fetch in open mode (Section 7.2).

- The path of a reference MUST contain at least 128 bits of cryptographically random entropy.
- An IDSP MUST NOT derive a reference path from the agent domain, operator, claim type, issuance order, issuance time or anything else an observer could enumerate.
- An IDSP MUST NOT expose any index, listing or search interface from which references can be obtained without already holding them.
- Relying parties, agents and IDSPs MUST NOT log, expose in telemetry, forward to third parties or republish a reference. Logs MAY record the reference's origin and a SHA-256 digest of the full URL.
- References are never published in DNS.

---

## 7. The IDSP Retrieval Protocol

The relying party dereferences a reference at the IDSP. The exchange is modelled on the OpenID Federation 1.0 fetch endpoint (§8.1) [OIDF] and on ISO/IEC 18013-5 server retrieval (§3.16, §3.17) [ISO18013-5], and is specified here because neither applies directly.

### 7.1. Request

The relying party sends an HTTPS GET to the reference, after the host check of Section 6.1.3 and under the fetch hardening of Section 7.7:

```http
GET /r/Vb2m7kQ1xZr9Lw0pT4yHcA HTTP/1.1
Host: verify.example.net
Accept: application/vc+sd-jwt
```

A relying party MAY also accept the optional Data Integrity form (Section 8.1) by listing its media type. `TODO(verify)`: the media type for a Data Integrity secured credential (`application/vc` in VCDM 2.0 is the expected value).

### 7.2. Modes

**Open mode.** The IDSP requires no authentication from the relying party. The reference is the bearer value, and it resolves to the release the operator made for any holder of that reference. This is the mode shipped code implements, and every IDSP MUST support it.

**Gated mode.** The IDSP authenticates the relying party and applies the release rule to that relying party. **Open (Section 19.4), proposed text:** the relying party signs its GET under Section 5 with a key in `_agentid` at its own domain, so a relying party is identified the same way an agent is; the IDSP verifies the signature, takes the relying party's domain from `keyid`, and serves the release the operator's rule permits for that domain. An IDSP that requires gated mode for a reference and receives an unauthenticated request responds 401.

### 7.3. Response

On success the IDSP responds 200 with `Content-Type: application/vc+sd-jwt` (VC-JOSE-COSE §6.1) [VC-JOSE-COSE] and the credential in SD-JWT compact form, carrying only the disclosures released to this relying party.

- 404: the reference is unknown or has been withdrawn.
- 410: the reference's IDSP path has been decommissioned (Section 17.6).
- 401 or 403: gated mode, relying party not authenticated or not permitted.
- 406: no acceptable representation. During the legacy window, an IDSP MAY serve the legacy JSON payload for `Accept: application/json` (Section 18).

A response shaped for one relying party MUST NOT be stored by shared caches; the IDSP MUST send `Cache-Control: private` or stricter on gated-mode responses. Open-mode responses MAY be cached by the relying party up to the credential's `validUntil`; current validity always comes from status (Section 12), not from cache freshness.

### 7.4. The Release Rule

The IDSP MUST serve, for a reference and a relying party, only the claims the operator's release rule permits for that relying party. Selective disclosure is how the IDSP does this without re-signing: it signs once and includes, per response, only the disclosures released (RFC 9901 §4.2) [RFC9901]. The IDSP, not a holder wallet, chooses the disclosures. An IDSP MAY instead issue a fresh credential per release.

The release rule has two halves. The agent decides whether to present a reference at all (Section 6.2.3); the IDSP decides what that reference releases to whom. Both are under the operator's control.

### 7.5. The Disclosure Record

The IDSP MUST keep a disclosure record of each release: which credential, about which operator, released to which relying party (or to an unauthenticated bearer in open mode), when, and under what consent. Consent fields MAY follow ISO/IEC TS 27560:2023 [ISO27560]. An IDSP that wants a tamper-evident log MAY register receipts with SCITT [RFC9943]. The disclosure record is the successor to the unlock tokens and consent trail of earlier designs. A trust framework sets retention and access rules for it.

### 7.6. Publication Gate

An IDSP MUST NOT release a credential for an agent until it has observed, under DNSSEC, an `_idsp` record at the agent domain naming the IDSP. This was a wire state (`pending_publication`) in earlier texts; it is now IDSP practice and does not appear on the wire.

### 7.7. Fetch Hardening

Relying parties fetch references and status lists from server-side infrastructure, and an untrusted agent supplies the reference. A conforming relying party MUST apply this hardened fetch profile to reference and status-list retrieval:

- fetch a reference only after the host check of Section 6.1.3;
- accept only `https` URLs; reject userinfo, fragments, invalid or ambiguous host syntax, and non-default ports unless a deployment profile permits a port;
- send no cookies, authorization headers, client certificates, proxy credentials or ambient application headers (other than the gated-mode signature of Section 7.2);
- send `Accept-Encoding: identity` or enforce a decompressed-size limit;
- resolve all A, AAAA and CNAME results and reject loopback, private, link-local, multicast, documentation, benchmark, unspecified, reserved and IPv4-mapped private addresses;
- pin the selected address for the TLS connection while keeping SNI and certificate validation for the original host, and verify the connected address;
- reject redirects;
- apply connect, header, idle and total timeouts and maximum body sizes;
- fetch from an egress-restricted context where practical;
- log only the origin and a digest of the full URL.

Web Bot Auth discusses request forgery risk in its security considerations (§6.7) [WEBBOTAUTH]. `TODO(verify)`: that section number against draft-ietf-webbotauth-httpsig-protocol-01.

---

## 8. The Credential

### 8.1. Data Model and Securing

A Groundmark credential is a W3C Verifiable Credential conforming to VCDM 2.0 [VCDM2], processed by type-specific rules: a Groundmark verifier compares `@context` and `type` as fixed strings and does not perform JSON-LD processing (VCDM 2.0 §6.3, `TODO(verify)` section number).

**Mandatory form.** The credential is secured as an SD-JWT per VC-JOSE-COSE §3.2 [VC-JOSE-COSE] and RFC 9901 [RFC9901], served as `application/vc+sd-jwt` (VC-JOSE-COSE §6.1). A conforming verifier MUST accept this form. An SD-JWT that uses no disclosures is an ordinary signed JWT; credentials that need no selective disclosure pay nothing for it.

**Optional form.** An IDSP MAY also serve the same credential secured with Data Integrity: `eddsa-jcs-2022` [VC-DI-EDDSA] for an Ed25519 IDSP, or `ecdsa-jcs-2019` [VC-DI-ECDSA] for an ES256 IDSP, by content negotiation (Section 7.1). It MUST NOT be the only form an IDSP serves. A verifier MAY ignore it.

### 8.2. Fields

| Property | Requirement | Source |
|---|---|---|
| `@context` | REQUIRED. `["https://www.w3.org/ns/credentials/v2", "<Groundmark context URL>"]`. `TODO(verify)`: the Groundmark context URL is not yet published; `https://groundmark.org/ns/v1` is a placeholder. | VCDM 2.0 §4.3 `TODO(verify)` |
| `type` | REQUIRED. `VerifiableCredential` plus exactly one Groundmark claim type's credential type (Section 14). | VCDM 2.0 §4.5 `TODO(verify)` |
| `id` | REQUIRED. Immutable, globally unique; a URN UUID is RECOMMENDED. | VCDM 2.0 §4.4 `TODO(verify)` |
| `issuer` | REQUIRED. `did:web:<idsp-domain>`, where `<idsp-domain>` is a bare host with no port or path. | VCDM 2.0 §4.7 |
| `validFrom`, `validUntil` | REQUIRED. `validUntil` is authoritative for expiry; there is no "expired" status. | VCDM 2.0 §4.9 |
| `credentialSchema` | REQUIRED. A JSON Schema for the claim type. | VCDM 2.0 §4.11; VC JSON Schema §2.1 [VC-JSON-SCHEMA] |
| `credentialSubject` | REQUIRED. Contains `agent_domain`, `claim_subject`, the claim's values, and the trust-framework claims `level`, `framework` and `jurisdiction` where used. `credentialSubject.id` is OPTIONAL and, when present, is the operator's own `did:web`. | VCDM 2.0 §4.8 |
| `evidence` | REQUIRED and non-empty. Section 9. | VCDM 2.0 §5.6 |
| `cnf` | REQUIRED. `{"jkt": "<agent key thumbprint>"}`. | RFC 7800 [RFC7800]; RFC 9449 `jkt` [RFC9449]; RFC 9901 §4.1.2; VC-JOSE-COSE §4.1.3 |
| `status` | REQUIRED. `{"status_list": {"idx": <n>, "uri": "<status list URL>"}}`. | Token Status List -21 §6.1 [TOKEN-STATUS-LIST] |
| JWS `kid` header | REQUIRED. A DID URL into the IDSP's `did:web` document, `did:web:<idsp-domain>#<kid>`. | VC-JOSE-COSE §4.2 |
| JWS `alg` header | REQUIRED. Section 8.6. | |

`TODO(verify)`: how the Token Status List `status` claim sits in a VCDM 2.0 payload secured with VC-JOSE-COSE, given that VCDM 2.0 has its own `credentialStatus` property. The map adopts `status.status_list`; confirm that VC-JOSE-COSE verifiers accept it, or whether `credentialStatus` with a Token Status List type is expected.

Groundmark-defined property names inside `credentialSubject` and `evidence` use snake_case, as the shipped schema did.

`agent_domain` is the agent domain the credential is about, in lowercase A-label form.

`level`, `framework` and `jurisdiction` are claims whose meaning the trust framework defines (Section 15.2). `framework`, when present, SHOULD equal the TRQP authority the relying party queries. `jurisdiction` uses ISO 3166-1 alpha-2, optionally followed by `-` and an ISO 3166-2 subdivision code.

### 8.3. The Claim Subject

No credential standard says whom an operator-level predicate is about: the operator, a human authorized to act for it, or a beneficiary. Groundmark states it in `credentialSubject.claim_subject`:

- `role` (REQUIRED): `agent`, `operator`, `authorized-human`, `beneficiary` or `intended-recipient`;
- `entity_type` (REQUIRED): `organization`, `natural-person`, `software-agent` or `other`;
- `relationship` (REQUIRED): for example `operator-of-agent`, `contact-for-agent`, `brand-agent`.

Each claim type defines the permitted combinations. A verifier MUST reject a credential whose `claim_subject` is not permitted for its type. An age predicate cannot apply to a corporate operator merely because the corporation runs the agent; it must name a natural person and a relationship.

### 8.4. Selective Disclosure Rules

- Claim values MAY be selectively disclosable (RFC 9901 §4.2).
- `evidence` MUST NOT be selectively disclosable, in whole or in part. An IDSP that could withhold evidence would defeat the method-disclosure obligation.
- `issuer`, `type`, `agent_domain`, `claim_subject`, `cnf`, `status`, `validFrom` and `validUntil` MUST NOT be selectively disclosable.
- One credential carries one claim. VCDM has no way to tie an evidence object to one claim among several, so one claim per credential is what makes the evidence plainly belong to the claim.

### 8.5. Key Binding

The credential names the agent's request-signing key in `cnf`, as the RFC 7638 thumbprint of that key in `jkt` form, whatever the key type.

No Key Binding JWT (RFC 9901 §4.3) is used. A Key Binding JWT must be signed with the `cnf` key, which is the agent's, while the credential is served by the IDSP, so it cannot be attached at serving time. It is also unnecessary: the agent proves possession of the `cnf` key on every request through the RFC 9421 signature that covers `Groundmark-Claim`. The request signature is the proof of possession. RFC 9901 leaves key binding to verifier policy, so this is within the RFC.

The verifier MUST compare `cnf.jkt` with the thumbprint of the exact key that verified the request (Section 11.1). The IDSP MUST verify possession of that key before issuing (Section 13.2).

### 8.6. Algorithms

This section records Elliot's ruling of 16 November 2026, which governs over map v1.0's D12 recommendation.

| Key | Signs | Rule |
|---|---|---|
| Agent request-signing key | RFC 9421 requests; named by `cnf` | Ed25519 MUST be supported; P-256 (`ecdsa-p256-sha256`) MAY be used. Unchanged. |
| IDSP credential-signing key and status-signing key | The SD-JWT credential; the Status List Token | **Ed25519 is the default.** An IDSP MAY sign with ES256 instead, and SHOULD when its credentials will be held in or verified by EU wallet tooling (HAIP, FIDES). |
| Verifiers | | MUST accept both Ed25519 and ES256 for credentials and status lists, so an IDSP's choice never fragments Groundmark. |

Ed25519 is the default on its merits: deterministic signing, small keys in DNS, the RFC 9421 and Web Bot Auth convention, and shipped code. The EU preference for P-256 comes from secure hardware and certification, and today Groundmark credentials are verified by Groundmark verifiers. ES256 is the specific exception for EU interoperability. The accepted trade: an IDSP picks its algorithm when it signs, without knowing who will verify; if EU interoperability becomes the common case, Groundmark carries two algorithms for good.

`TODO(verify)`: the JOSE `alg` value for Ed25519 in an SD-JWT. It is either `EdDSA` [RFC8037] or the fully specified `Ed25519` from RFC 9864. Check before this is fixed; verifiers may need to accept both.

To test, not assume: that a HAIP or FIDES verifier reading a Groundmark credential accepts an Ed25519 key inside `cnf`. It should, since there is no Key Binding JWT for it to check. If it does not, the agent uses a P-256 key, which is why P-256 is allowed.

### 8.7. Worked Example (non-normative)

The decoded JWS header and payload of an `operator-verified` credential. The display name is a selectively disclosable claim, released to this relying party.

```json
{
  "alg": "TODO(verify): EdDSA or Ed25519",
  "typ": "vc+sd-jwt",
  "kid": "did:web:verify.example.net#cred-2026-11"
}
```

`TODO(verify)`: the `typ` header value VC-JOSE-COSE §3.2 requires.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://groundmark.org/ns/v1"
  ],
  "type": ["VerifiableCredential", "OperatorVerifiedCredential"],
  "id": "urn:uuid:0190fbf6-07f0-7c1c-8a9c-2f35610297a1",
  "issuer": "did:web:verify.example.net",
  "validFrom": "2026-11-16T12:00:00Z",
  "validUntil": "2027-05-16T00:00:00Z",
  "credentialSchema": {
    "id": "https://groundmark.org/schemas/operator-verified/v1.json",
    "type": "JsonSchema"
  },
  "credentialSubject": {
    "agent_domain": "purchasing.acmecorp.example",
    "claim_subject": {
      "role": "operator",
      "entity_type": "organization",
      "relationship": "operator-of-agent"
    },
    "verified": true,
    "level": 1,
    "framework": "example-trust-framework",
    "jurisdiction": "CA",
    "_sd": ["Zq9mL3...example...digest"]
  },
  "evidence": [
    {
      "type": "GroundmarkMethodExecution",
      "profile": "groundmark-operator-accountability",
      "profile_version": "1.0",
      "method_id": "dnssec-domain-challenge",
      "method_version": "1.0",
      "execution_mode": "idsp-direct",
      "performed_by": { "role": "idsp", "domain": "verify.example.net" },
      "performed_at": "2026-11-16T11:48:00Z",
      "evidence_class": ["domain-control"]
    },
    {
      "type": "GroundmarkMethodExecution",
      "profile": "groundmark-operator-accountability",
      "profile_version": "1.0",
      "method_id": "agent-key-proof-of-possession",
      "method_version": "1.0",
      "execution_mode": "idsp-direct",
      "performed_by": { "role": "idsp", "domain": "verify.example.net" },
      "performed_at": "2026-11-16T11:52:00Z",
      "evidence_class": ["cryptographic-key-control"]
    },
    {
      "type": "GroundmarkMethodExecution",
      "profile": "groundmark-operator-accountability",
      "profile_version": "1.0",
      "method_id": "organization-existence-check",
      "method_version": "1.0",
      "execution_mode": "authoritative-source-query",
      "performed_by": { "role": "idsp", "domain": "verify.example.net" },
      "performed_at": "2026-11-16T11:55:00Z",
      "source_class": "corporate-registry",
      "source_domain": "registry.example.gov",
      "source_observed_at": "2026-11-16T11:55:00Z",
      "evidence_class": ["organization-record"]
    }
  ],
  "cnf": { "jkt": "mBk0ZxJ4exAMPLEwBhlM0GOf3a6wS9mO7example8" },
  "status": {
    "status_list": {
      "idx": 4711,
      "uri": "https://verify.example.net/status/2026-11"
    }
  },
  "_sd_alg": "sha-256"
}
```

The disclosure released with it carries `["<salt>", "operator_asserted_display_name", "Acme Corp"]`. Method identifiers are placeholders pending the vocabulary (Section 9.4); relying parties MUST tolerate unrecognized identifiers.

---

## 9. Method Disclosure

This is core element 2. A Groundmark IDSP attests to methods, not only to conclusions: it states what it did, and stakes its reputation on the accuracy of that statement. The trust decision belongs to the relying party.

### 9.1. The Requirement

VCDM 2.0 makes `evidence` optional. Groundmark makes it REQUIRED and non-empty. Every credential MUST carry at least one evidence object describing a method execution that supports its claim. A credential without evidence is not a Groundmark credential, whatever else it carries. The obligation applies to self-issued credentials too.

### 9.2. Shape

VCDM 2.0 §5.6 defines `evidence` as one or more objects, each with a required `type` and optional `id`, and leaves every other property to the evidence type. Groundmark uses one evidence object per method execution, of type `GroundmarkMethodExecution`, registered in the VC Extensions note §2.3 [VC-EXTENSIONS]. One object per execution is how other evidence vocabularies are built, and it lets a policy ask for "an execution of method X" directly.

Each object carries:

| Field | Requirement | Meaning |
|---|---|---|
| `type` | REQUIRED | `GroundmarkMethodExecution` |
| `profile`, `profile_version` | REQUIRED | The IDSP practice profile under which the verification was performed, and its version |
| `method_id` | REQUIRED | Immutable identifier of the method |
| `method_version` | REQUIRED | Version of the method, technology or source integration |
| `execution_mode` | REQUIRED | Section 9.3 |
| `performed_by` | REQUIRED | `{role, domain}` plus optional `key_id`, `key_thumbprint` of a key actually used for that execution. `role` is `idsp` or `idtp`. An IDSP MUST NOT put its credential-signing key here merely because that key later signs the credential. |
| `performed_at` | REQUIRED | Completion time [RFC3339] |
| `valid_until` | OPTIONAL | Time after which the execution cannot support new issuance without refresh |
| `evidence_class` | OPTIONAL | Categories of evidence examined, for example `domain-control`, `cryptographic-key-control`, `organization-record`, `government-issued-id`, `biometric-liveness` |
| `source_class`, `source_domain`, `source_observed_at` | OPTIONAL; REQUIRED for `authoritative-source-query` where the profile requires | The authoritative source and freshness |
| `provider` | OPTIONAL | `{domain, service?, version?}`: a material technology or service provider different from `performed_by` |
| `receipt_digest` | OPTIONAL | Digest of a private signed Method Receipt. Kept as a hook while Method Receipts are deferred (Section 13.4). |
| `method_detail` | OPTIONAL | Free text for human review; never sufficient for policy |

Field names mirror OpenID eKYC and Identity Assurance [OIDC-IDA] and draft-loffredo-regext-rdap-verified-contacts-04 [LOFFREDO] where they overlap.

### 9.3. Execution Modes

- `idsp-direct`: the IDSP performs the check with its own personnel, systems and process.
- `idsp-operated-technology`: the IDSP performs the check using material third-party technology and controls the issuance decision. `performed_by.role` is `idsp`; `provider` names the technology provider, so an IDSP-run vendor tool is not mistaken for a managed IDTP execution.
- `authoritative-source-query`: the IDSP directly controls a query to an authoritative source; the `source_` fields identify it.
- `idtp-managed-service`: an IDTP executes the method and returns a result to the IDSP. `performed_by.role` is `idtp`. When an IDTP controls an authoritative-source query, this mode is used and the `source_` fields are populated.

### 9.4. Vocabulary

The method identifier and evidence-class vocabulary is maintained with this specification, not in an IANA registry. Until it is populated, identifiers in examples are placeholders, and relying parties MUST ignore, not error on, identifiers they do not recognize. A policy can only be satisfied by identifiers it recognizes.

### 9.5. Accountability

There is no cryptographic check that an IDSP did what its evidence says. The obligation rests on the IDSP's reputational and contractual exposure and on the trust framework's audit of disclosure accuracy (Section 15). An IDSP that claims verification it did not perform, omits a material provider, or misstates an evidence class has failed the central duty of the role. Disclosure of an IDTP does not transfer the IDSP's accountability to it (Section 13.3).

---

## 10. IDSP Keys and `did:web`

### 10.1. The `did:web` Document

An IDSP MUST publish a `did:web` document [DID-WEB] for `did:web:<idsp-domain>`, served at `https://<idsp-domain>/.well-known/did.json`. Its keys are verification methods (CID 1.0 §2.2) [CID], retrieved per CID 1.0 §3.3:

- the credential-signing key, listed under `assertionMethod` (CID 1.0 §2.3.2);
- the status-signing key, as a separate verification method, also under `assertionMethod`.

Each verification method's fragment MUST equal the `kid=` of the matching `_agentid` record. The IDSP MUST use different private keys for credential signing and status signing.

### 10.2. The DNSSEC Cross-Check

The same keys MUST be published at `_agentid.<idsp-domain>` with `purpose=attestation-signing` (the shipped purpose name, kept for the credential-signing key) and `purpose=status-signing` respectively, in a DNSSEC-signed zone. A Groundmark verifier MUST:

1. resolve the `did:web` document and select the verification method named by the JWS `kid`;
2. retrieve `_agentid.<idsp-domain>` under Section 4.3 and select the record whose `kid=` equals the fragment and whose `purpose=` matches the use (credential or status);
3. confirm that the two carry the same public key and algorithm. A mismatch, a missing record, or a DNSSEC failure MUST cause rejection.

`did:web` rests on the web PKI. The cross-check is what makes an IDSP key Groundmark-trustworthy: it must be authorized both by the IDSP's HTTPS origin and by its DNSSEC-signed zone.

### 10.3. Why No New DID Method

A Groundmark DID method would force every resolver to do the DNSSEC step. It is not worth a method. Groundmark verifiers must do the cross-check anyway; a generic VC verifier that does not know Groundmark accepts an IDSP's keys on the web certificate alone, which leaves it no worse off than with any other `did:web` issuer (Section 17.3). If the W3C DID Methods Working Group later standardizes `did:web`, the cross-check stays a Groundmark rule either way.

### 10.4. Operators With a DID

An operator MAY have its own `did:web` and, where it does, the IDSP MAY set `credentialSubject.id` to it. No operator is required to have a DID. This is the slot an agent framework that roots delegation in a responsible party's DID, such as KYA-OS [KYA-OS], can use to learn who that party is.

---

## 11. Verification

### 11.1. The Four Bindings

These bindings are not provided by any VC specification. They are what make a credential a Groundmark credential, and a verifier MUST reject a credential unless all four hold:

1. **Agent.** `credentialSubject.agent_domain` equals the agent domain being evaluated, the one resolved from the request's `keyid`.
2. **Key.** `cnf.jkt` equals the agent key thumbprint of the exact key that verified the RFC 9421 request.
3. **Issuer.** `issuer` equals `did:web:<h>`, where `<h>` is the `idsp=` value of a DNSSEC-validated `_idsp` record for the agent domain.
4. **Reference.** The host of the presented `ref` is that same `<h>` (Section 6.1.3), checked before the fetch.

In addition, the credential's type MUST be the credential type of the presented `claim-type` (Section 14.1). All domain comparisons are on lowercase A-labels with no trailing dot.

### 11.2. Verification Steps

After the request steps of Section 5.6 have succeeded:

1. Confirm `Groundmark-Claim` is present once and covered (Sections 6.1.1, 6.1.2).
2. Perform the host check (Section 6.1.3). Binding 4.
3. Fetch the reference under Section 7, with fetch hardening (Section 7.7).
4. Verify the SD-JWT per VC-JOSE-COSE §5.4 [VC-JOSE-COSE] and RFC 9901, with the issuer key obtained and cross-checked under Section 10. Accept Ed25519 and ES256 (Section 8.6).
5. Validate `@context`, `type` and `credentialSchema` as fixed values for a recognized claim type; validate `credentialSubject` against the claim type's schema and its `claim_subject` rules (Section 8.3). An unrecognized claim type MAY be verified but MUST NOT satisfy policy.
6. Confirm `evidence` is present, non-empty and not selectively disclosed (Sections 8.4, 9.1).
7. Check bindings 1, 2 and 3 (Section 11.1) and the claim-type match.
8. Check `validFrom` and `validUntil` against the verifier's clock with its skew policy.
9. Check status (Section 12).
10. Check issuer authorization: by TRQP against the anchors the relying party trusts, by local configuration, or both (Section 15).
11. Apply transaction policy, including the policy match of Section 6.1.4.
12. Consume the nonce (Section 5.5).

Implementations SHOULD return a structured result that separates cryptographic validity from policy satisfaction, using the codes in Appendix A.

---

## 12. Status and Revocation

### 12.1. Token Status List

Credential status uses Token Status List, draft -21 [TOKEN-STATUS-LIST], with a 2-bit list:

| Value | Token Status List meaning (§7) | Groundmark state |
|---|---|---|
| `0x00` | VALID | active |
| `0x01` | INVALID | revoked |
| `0x02` | SUSPENDED | suspended |
| `0x03` | application-specific | superseded: a newer credential replaces this one |

`TODO(verify)`: whether Token Status List has been published as an RFC; the latest found is draft -21, and this document pins -21 until it is.

The Status List Token is signed with the IDSP's status-signing key (Section 10). Its `iat`, `exp` and `ttl` (§5.1) replace the earlier `this_update`, `next_update` and `sequence`.

There is no status entry for expiry: `validUntil` is authoritative. There is no `pending_publication` state on the wire (Section 7.6) and no `reason_code`.

### 12.2. Status Lists Are Public

A status list is a static resource any cache can serve. The IDSP MUST serve it without authentication and MUST NOT vary it per relying party.

### 12.3. Two Verifier Rules

Token Status List leaves these to the verifier. Groundmark fixes them:

1. **Stale means not valid.** A verifier MUST NOT accept a credential on a Status List Token whose `exp` has passed, or that is older than its `ttl` allows. Any grace period for low-risk operations is relying-party policy under its trust framework, and its use SHOULD be logged.
2. **Revocation is terminal.** A verifier that has seen a credential as `0x01` MUST NOT accept that credential again, whatever a later status list says. An IDSP MUST NOT reinstate a revoked credential; it issues a new credential with a new `id` and status index.

### 12.4. DNS Withdrawal Versus Revocation

Removing an `_idsp` record (Section 4.2.2) or an `_agentid` key withdraws a publication. Changing a status list entry revokes or suspends a credential. They are different controls and implementations MUST NOT present one as the other. An operator responding to compromise can withdraw at once; an IDSP revokes individual credentials.

---

## 13. The IDSP Role

### 13.1. What an IDSP Does

An IDSP:

1. verifies claims about operators and agents, by methods it discloses;
2. issues credentials bound to a specific agent domain and agent key;
3. serves them by reference under the retrieval protocol and the operator's release rule;
4. publishes its keys in `did:web` and `_agentid`, under DNSSEC;
5. publishes status;
6. keeps the disclosure record;
7. is accountable to relying parties for what it serves.

An IDSP is an auditor, not a gatekeeper. Its duty is to characterize accurately what it did; the relying party decides what that is worth.

### 13.2. Issuance Requirements

Before issuing a credential, an IDSP MUST:

- bind the claim to a specific agent domain and the exact agent key it will name in `cnf`;
- verify the operator's control of the agent domain by a DNSSEC-authenticated challenge or an equivalently strong method, or, for a provider-hosted agent, an authenticated provider binding that authorizes the hosted agent for the operator;
- verify possession of the agent's private key: by the operator for an operator-controlled key, or by the custodian, together with an explicit authorization binding operator, agent domain and key, for a custodied key;
- record these executions in `evidence`, including the custodian or hosting provider as a material performer or provider where there is one.

An IDSP MAY verify and keep operator attributes in a private account before any agent exists. That account state is not a credential and is not part of this protocol.

### 13.3. Issuer and IDSP as Separable Roles

The IDSP is the single party accountable to the relying party for what it serves, whoever performed the methods or issued the credential. That accountability cannot be delegated. An IDSP MUST NOT describe a credential as policy-satisfying solely because an IDTP performed a method.

In this version the issuer and the IDSP are one party, and the IDSP serves the bare credential. Where they differ in a later version, the IDSP can sign a Verifiable Presentation as `holder` over credentials others issued (VCDM 2.0 §4.13) [VCDM2].

### 13.4. Identity Technology Providers

An IDTP supplies methods to IDSPs and appears in `evidence` as `performed_by` or `provider`. An IDSP and an IDTP are two functions, often performed by one organization; each function is keyed and evaluated separately. Private signed Method Receipts from IDTP to IDSP, with IDTP keys under a `method-receipt-signing` purpose, are deferred, not dropped: provenance from authoritative sources is central to what Groundmark says an agent can do, and they will return. `receipt_digest` keeps the hook. Dependency indexing and incident handling are accreditation criteria (Section 15).

### 13.5. Key Protection and Rotation

An IDSP MUST protect its credential-signing and status-signing keys with controls appropriate to their different use, hardware-backed where available, and SHOULD publish its rotation policy. A key rotation must be made in both places a key is published: the `did:web` document and `_agentid` (Section 17.5).

---

## 14. Claim Types

### 14.1. Naming

Each Groundmark claim type has:

- a short name, used in `Groundmark-Claim` and `Groundmark-Accept`, for example `operator-verified`;
- a credential type, used in the credential's `type`, for example `OperatorVerifiedCredential`, defined in the Groundmark context;
- a JSON Schema, named by `credentialSchema` (VCDM 2.0 §4.11; VC JSON Schema §2.1).

A claim type defined by anyone other than this specification is named by a type URI under a domain its definer controls, and that URI appears in both the header and the credential's `type`. This replaces the `x-<domain>-<name>` construction and closes the dot-versus-hyphen conflict between the earlier drafts.

The short names and credential type names in this section are proposed text for review.

### 14.2. `operator-verified`

The baseline type, against which the DNS and key bindings are written. An identifiable operator controls the agent and has accepted the IDSP's accountability terms. It establishes existence and accountability, not capability, compliance or brand authority.

- Credential type: `OperatorVerifiedCredential`.
- `claim_subject`: role `operator`; entity type `organization`, `natural-person` or `other`; relationship `operator-of-agent`.
- Claims: `verified` (REQUIRED, `true`; a credential is never issued with `false`); `operator_asserted_display_name` (OPTIONAL, selectively disclosable, released only where the operator chose to disclose it).
- Required executions: domain control and agent-key possession (Section 13.2), operator existence, and acceptance of terms. Email confirmation alone is not sufficient.

`operator_asserted_display_name` is operator-chosen. Relying parties MUST NOT use it as a policy input or a brand signal, and SHOULD label it as operator-asserted in any interface. Brand authority needs a brand-authorization claim type (Section 14.5).

### 14.3. Bounded Predicates

A bounded predicate attests one fact without the underlying data: "over 18", not a date of birth. Groundmark defines predicates about an operator or about a human behind an operator. No existing schema treats an operator, or a responsible human behind one, as subject; that is why `claim_subject` exists. Naming mirrors the EUDI `age_over_NN` pattern [EUDI-ARF] and the shape follows DIF Proof of Age [DIF-POA]. `TODO(verify)`: the exact EUDI and ISO/IEC 18013-5 attribute definitions, which were not checked (the ISO text is paywalled).

**`age-over-NN`** (`age-over-18`, `age-over-21`, and other thresholds by the same pattern).

- Credential type: `AgeOverCredential`.
- `claim_subject`: role `authorized-human`, `beneficiary` or `intended-recipient`; entity type `natural-person`. A verifier MUST reject an age predicate whose `entity_type` is `organization` or `software-agent`.
- Claims: `age_over_NN: true`, for example `age_over_18: true`.

**`canadian-presence`.** The operator has a verified presence in Canada.

- Credential type: `CanadianPresenceCredential`.
- `claim_subject`: role `operator`; entity type `organization` or `natural-person`; relationship `operator-of-agent`.
- Claims: `present: true`, `jurisdiction: "CA"`.

Further bounded predicates SHOULD follow the same discipline. A claim that would need richer personal data SHOULD be decomposed into bounded predicates.

### 14.4. Dropped: Self-Asserted Claims

`operator-contact` and every other self-asserted DNS claim are dropped. An operator that wants to state a contact can self-issue (Section 4.4).

### 14.5. The Attestation Library

The other claim types of earlier texts, `jurisdiction-licensed`, `kyc-basic`, `kyc-enhanced` and `brand-authorized`, move to the Groundmark attestation library as credential types with JSON Schemas, to be offered to DIF Credential Schemas `community-schemas`, which has no organization schema today. They are not part of this protocol. Governance of the library is a trust framework matter.

---

## 15. Accreditation and Trust Frameworks

### 15.1. Issuer Authorization

A cryptographically valid credential from an unauthorized issuer MUST NOT satisfy policy. A relying party authorizes an IDSP for a claim type, framework, jurisdiction, method profile and level by either or both of:

- a TRQP v2.0 §6 authorization query [TRQP] against each trust anchor it trusts; and
- local configuration.

Validity is anchor-neutral: no anchor is the Groundmark anchor, and this document defines no central issuer list. A self-issuing operator is unaccredited by construction. How a relying party composes answers when anchors disagree is a trust framework matter.

Governance of accreditation is expected to follow the ToIP Governance Metamodel [TOIP-GMM], with the vLEI Ecosystem Governance Framework v4.0 [VLEI-EGF] as template.

### 15.2. Levels

The level taxonomy moves to the trust framework. `level` remains a claim in the credential (Section 8.2), and its meaning is the trust framework's. The intended taxonomy, for the trust framework to define:

- **Level 0:** no credential; a verified key only. This one stays in the protocol (Section 3).
- **Level 1:** operator accountability.
- **Level 2:** a specific bounded fact.
- **Level 3:** a fact meeting a named legal or regulatory standard.

These levels sort claims by kind. They are not grades of identity proofing, and they are not defined by reference to eIDAS levels of assurance [EIDAS-LOA] or NIST identity assurance levels [NIST-IAL], which are related work.

### 15.3. What Moves to the Trust Framework

Accreditation criteria; method-disclosure audit; level definitions; fail-open and fail-closed rules by level and grace-period logging; dependency indexing and incident handling for IDSPs and IDTPs; disclosure-record retention; composition of anchors.

---

## 16. Key Rotation and Identity Reset

### 16.1. Agent Key Rotation

1. If the current `_agentid` record has no `kid=`, republish it with one and wait one TTL.
2. Publish the new key as a second record with a distinct `kid=`.
3. Obtain reissued credentials naming the new key in `cnf` (Section 16.3).
4. Sign with the new key, using the `<domain>#<kid>` form.
5. After at least twice the TTL, remove the old record.

### 16.2. Identity Reset

The authenticated identity is the agent identity instance, `(agent domain, agent key thumbprint)`. A request from the same domain with a different thumbprint is a new instance unless the relying party verifies and accepts a separate continuity proof, which this document does not define. Relying parties MUST NOT carry allowlists, reputation, limits, standing approvals or earlier credentials across an identity reset on the strength of the FQDN alone.

### 16.3. Credentials Follow the Key

A credential names one key in `cnf`. A key change means the IDSP reissues with the new `cnf`. A credential naming the old key fails binding 2 once the old key is withdrawn.

---

## 17. Security Considerations

### 17.1. DNSSEC

Without DNSSEC validation, cache poisoning could substitute an attacker's key or IDSP name, and every later check would be meaningless. Section 4.3 is therefore mandatory, not advisory.

### 17.2. Replay

The 300-second `created` window limits replay but does not prevent it within the window. State-changing operations MUST use the nonce profile of Section 5.5. A read followed by a separate write is not an atomic consume. `@authority` coverage prevents cross-service replay.

### 17.3. `did:web` and Generic Verifiers

`did:web` resolves over HTTPS and rests on web certificates, not DNSSEC. A generic VC verifier that does not implement Groundmark will accept an IDSP's keys on the web certificate alone and will not perform the cross-check of Section 10.2 or the bindings of Section 11.1. Such a verifier is no worse off than with any other `did:web` issuer, but it is not performing Groundmark verification, and its results MUST NOT be described as Groundmark results.

### 17.4. Re-Hosted Credentials

A credential copied to another location and presented by reference fails the host check, because the new host is not named in the agent's `_idsp`. A credential presented for a different agent fails binding 1. A credential presented with a different key fails binding 2. This replaces the signed `endpoint_url` of earlier texts.

### 17.5. IDSP Compromise

Compromise of the credential-signing key permits forged credentials until the key is removed from both `did:web` and `_agentid` and caches expire. Compromise of the status-signing key permits forged status but cannot create a credential, and cannot reinstate one a verifier has seen revoked (Section 12.3). Purpose separation limits damage only where verifiers enforce it. The `did:web` document is a second place a compromised key must be rotated; an IDSP that rotates only one leaves verifiers that check only that one exposed, which is one reason the cross-check requires both.

### 17.6. IDSP Host Decommissioning

A reference embeds the IDSP host. An IDSP MUST NOT release a host used in references until every credential served from it has expired or been revoked, and SHOULD serve 410 at decommissioned paths for at least 90 days first. Because the host must also appear in the agent's `_idsp`, a third party that later acquires the host is not named by any operator's zone unless an operator still names it; operators SHOULD remove `_idsp` records for IDSPs they no longer use.

### 17.7. Agent Key Compromise

An attacker holding an agent key can impersonate the agent and present its references until the `_agentid` record is removed and caches expire. Operators SHOULD keep TTLs at 300 seconds or less and rehearse rotation. There is no kill signal other than DNS withdrawal and credential revocation.

### 17.8. Domain Expiry and Registrar Compromise

Expiry, re-registration, and registrar or DNS operator compromise can put a different party in control of an agent domain. DNSSEC authenticates the data, not the continuity of the registrant. A key thumbprint change without an accepted continuity proof is an identity reset (Section 16.2).

### 17.9. Current-Key Provenance Versus Operator Assurance

Request verification establishes control of the published key and nothing more. Where a custodian operates the key, it establishes that the custodied key signed. Operator accountability comes only from a verified credential evaluated under the relying party's policy.

### 17.10. Signature Validity Is Not Authorization

A valid credential signature proves the IDSP's key signed it. It does not prove the IDSP is trusted, competent or authorized for the claim type, method profile, jurisdiction or level (Section 15.1).

### 17.11. Cross-Claim Consistency

Credentials from different IDSPs may describe different underlying operator identities; IDSPs do not coordinate. Relying parties MUST NOT infer a common operator across IDSPs from a shared agent domain alone. The optional operator `did:web` in `credentialSubject.id` (Section 10.4) is the operator handle that lets a relying party check consistency where operators have one.

### 17.12. Gated-Mode Responses

A response shaped for one relying party that leaks into a shared cache would release one relying party's claims to another. Section 7.3 forbids shared caching of gated responses.

---

## 18. Migration and the Legacy Window

Request signing and `_agentid` do not change, so Level 0 keeps working everywhere with no edits. Everything that changes is in the credential path.

| System | What changes | What is only added |
|---|---|---|
| Verifiers (`poc/lib` and the production library) | Credential parse and verify: JSON with JCS becomes SD-JWT. Status: the revocation and status modules become a Token Status List client. Claim resolution: `_agentclaim` open and committed references both go. | `did:web` resolution with the DNS cross-check; ES256 alongside Ed25519; an optional TRQP client |
| Reference IDSP | Issuance and signing format; status endpoint; served content type | `/.well-known/did.json`; purpose-separated credential and status keys; a status list publisher; gated mode; the disclosure record |
| Operators | `_agentclaim` records replaced by one `_idsp` record per IDSP | |

**The legacy window.** So that nothing breaks on the day this specification is adopted:

- An IDSP serves both formats at the same reference URL, chosen by `Accept`: `application/vc+sd-jwt` returns the credential of Section 8; `application/json` returns the legacy schema 1.x payload.
- A verifier MAY continue to read `_agentclaim` records and verify legacy payloads, open and committed references both, only under an explicit legacy policy.
- **Open (Section 19.3):** the date the legacy window closes. After it, IDSPs stop serving `application/json` and verifiers drop legacy policy.

`TODO(verify)`: what the production verifier and the live reference IDSP run today: schema 1.0 with a revocation endpoint, or 1.1 with the signed status object. The PoC verifier reads `revocation_endpoint` and has no `status_url` handling, so it at least is on schema 1.0. This sets the size of the status break. Mark knows the answer.

`TODO(verify)`: that the IIW live path used open `_agentclaim` references, as assumed because the PoC verifier supports nothing else.

---

## 19. Open Issues

These are open, not decided.

### 19.1. Bundles (waiting on Mark)

Under this design every claim reaches a relying party by presentation, and Section 6.1.1 allows one reference per request. A policy that needs two claims together cannot be met in one request.

Recommendation in map v1.0, for Mark's view: one reference resolves to the bundle of credentials the IDSP will release to that relying party, which is the IDSP being accountable for the bundle; and the header may carry one reference per IDSP, for agents with more than one. Questions the design must settle include: whether a bundle is a Verifiable Presentation signed by the IDSP as `holder` (Section 13.3) or several SD-JWTs in one response; how `claim-type` is expressed for a bundle; how the four bindings apply to each member; and whether more than one `Groundmark-Claim` field, or a list in one field, carries several references.

### 19.2. P-256 Key Encoding in `_agentid` (Mark)

ES256 IDSPs and P-256 agents need a `k=` value and a stated `p=` encoding for a P-256 public key (for example compressed or uncompressed SEC1 point, Base64url). The same key appears in the IDSP's `did:web` document and the two must compare equal (Section 10.2), so the encoding must make that comparison exact.

### 19.3. The Legacy-Window Date

Section 18 needs a date on which legacy formats and `_agentclaim` reading end.

### 19.4. Gated-Mode Relying Party Authentication

Map v1.0 names a gated mode but does not specify how the relying party authenticates. Section 7.2 proposes RFC 9421 signing under the relying party's own `_agentid`. This is proposed text, not a decision.

### 19.5. Claim-Type Names

The short names and credential type names in Section 14 (`OperatorVerifiedCredential`, `AgeOverCredential`, `CanadianPresenceCredential`) and the Groundmark context URL are proposed, not decided.

---

## 20. Related Work

Groundmark composes with these; it does not compete with them.

- **DKIM** [RFC6376]. Groundmark's key publication follows DKIM's pattern of a public key in a TXT record under a reserved label.
- **AAuth** [AAUTH]. AAuth binds an agent key discovered over HTTPS, signs with RFC 9421, and keeps claims inside tokens that are never published; a resource states requirements in an `AAuth-Requirement` field. This design now matches AAuth's privacy default: no claim is published, and `Groundmark-Accept` plays the requirement role. The protocols differ in their anchor: AAuth anchors the key at an HTTPS endpoint; Groundmark anchors it in DNSSEC-signed DNS and adds accountable third-party credentials. An AAuth agent's domain can carry Groundmark records and a resource can evaluate both.
- **ANSv2 and DNS-AID.** Both address naming and discovery of agents. Groundmark addresses request authentication and accountability, under different DNS labels, at the same domains.
- **KYA-OS** [KYA-OS]. Agents support `did:key` and `did:web`, delegation is a chain of VCs rooted at a responsible party's DID, and reputation is scoped to that party. It does not say how anyone verifies who the responsible party is. A Groundmark credential about an operator's `did:web` fills that slot (Section 10.4).
- **EUDI ARF and HAIP.** The EU wallet architecture [EUDI-ARF] and the High Assurance Interoperability Profile [HAIP] are why ES256 is supported (Section 8.6) and why SD-JWT is the mandatory form. FIDES DIIP v5 [FIDES-DIIP] mandates VCDM 2.0 secured as SD-JWT.
- **High-assurance DIDs with DNS** [CARTER], §3.4, and **DANE for DIDs** [RANJBAR]. Prior art for binding DID keys to DNSSEC.
- **`_trustregistry`** [LATOUR]. Prior art for a DNS pointer to a trust registry; expired.
- **OpenID Federation 1.0** [OIDF]. The fetch endpoint (§8.1) models the retrieval protocol; `authority_hints` in an Entity Statement (§3, `TODO(verify)`) is the nearest analogue of the `_idsp` pointer.
- **x402.** An HTTP-native payment protocol; `Groundmark-Accept` on a 402 lets payment and identity requirements arrive together.

---

## 21. References

`TODO(verify)` items in this list are also collected in Appendix D. Section numbers cited in the text are as verified in the 7 November 2026 landscape survey and in map v1.0, except where marked.

### 21.1. Normative

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
- **[RFC3339]** Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339.
- **[RFC4033]** Arends, R., et al., "DNS Security Introduction and Requirements", RFC 4033.
- **[RFC4648]** Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648.
- **[RFC7638]** Jones, M. and N. Sakimura, "JSON Web Key (JWK) Thumbprint", RFC 7638.
- **[RFC7800]** Jones, M., Bradley, J. and H. Tschofenig, "Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)", RFC 7800.
- **[RFC8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032.
- **[RFC8037]** Liusvaara, I., "CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)", RFC 8037.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
- **[RFC8552]** Crocker, D., "Scoped Interpretation of DNS Resource Records through \"Underscored\" Naming of Attribute Leaves", BCP 222, RFC 8552.
- **[RFC9449]** Fett, D., et al., "OAuth 2.0 Demonstrating Proof of Possession (DPoP)", RFC 9449. Cited for the `jkt` confirmation method.
- **[RFC9421]** Backman, A., Richer, J. and M. Sporny, "HTTP Message Signatures", RFC 9421.
- **[RFC9530]** Polli, R. and L. Pardue, "Digest Fields", RFC 9530.
- **[RFC9651]** Nottingham, M. and P-H. Kamp, "Structured Field Values for HTTP", RFC 9651.
- **[RFC9901]** "Selective Disclosure for JSON Web Tokens" (SD-JWT), RFC 9901. `TODO(verify)`: authors and date for the full citation.
- **[RFC9864]** Cited for the fully specified `Ed25519` JOSE algorithm. `TODO(verify)`: title, authors, and whether it governs the `alg` value used here (Section 8.6).
- **[VCDM2]** W3C, "Verifiable Credentials Data Model v2.0".
- **[VC-JOSE-COSE]** W3C, "Securing Verifiable Credentials using JOSE and COSE".
- **[VC-JSON-SCHEMA]** W3C, "Verifiable Credentials JSON Schema Specification".
- **[CID]** W3C, "Controlled Identifiers v1.0".
- **[DID-WEB]** W3C Credentials Community Group, "did:web Method Specification". `TODO(verify)`: current status; the W3C DID Methods WG had not been confirmed as launched (map v1.0, section 7).
- **[TOKEN-STATUS-LIST]** "Token Status List", draft-ietf-oauth-status-list-21. `TODO(verify)`: RFC status.

### 21.2. Informative

- **[AAUTH]** Hardt, D., "AAuth Protocol", draft-hardt-oauth-aauth-protocol-10.
- **[Cameron2005]** Cameron, K., "The Laws of Identity", May 2005.
- **[CARTER]** draft-carter-high-assurance-dids-with-dns-08.
- **[DIF-POA]** Decentralized Identity Foundation, Proof of Age. `TODO(verify)`: exact document title and version.
- **[EIDAS-LOA]** Commission Implementing Regulation (EU) 2015/1502 on levels of assurance for electronic identification means.
- **[EUDI-ARF]** European Commission, "EUDI Wallet Architecture and Reference Framework", v3.0.0, 21 July 2026.
- **[FIDES-DIIP]** FIDES, "Decentralized Identity Interop Profile", v5.
- **[HAIP]** OpenID Foundation, "OpenID4VC High Assurance Interoperability Profile 1.0".
- **[ISO18013-5]** ISO/IEC 18013-5, "Personal identification: ISO-compliant driving licence, Part 5: Mobile driving licence (mDL) application".
- **[ISO27560]** ISO/IEC TS 27560:2023, "Privacy technologies: Consent record information structure".
- **[KYA-OS]** Decentralized Identity Foundation, KYA-OS SPEC.md, 1.0.0.
- **[LATOUR]** draft-latour-dns-and-digital-trust-02 (expired).
- **[LOFFREDO]** draft-loffredo-regext-rdap-verified-contacts-04.
- **[NIST-IAL]** NIST Special Publication 800-63A, identity assurance levels.
- **[OID4VP]** OpenID Foundation, "OpenID for Verifiable Presentations 1.0".
- **[OIDC-IDA]** OpenID Foundation, "OpenID Connect for Identity Assurance" (eKYC and IDA).
- **[OIDF]** OpenID Foundation, "OpenID Federation 1.0".
- **[RANJBAR]** draft-ranjbar-dane-did. `TODO(verify)`: revision number.
- **[RFC6376]** Crocker, D., Hansen, T. and M. Kucherawy, "DomainKeys Identified Mail (DKIM) Signatures", RFC 6376.
- **[RFC8484]** Hoffman, P. and P. McManus, "DNS Queries over HTTPS (DoH)", RFC 8484.
- **[RFC9334]** Birkholz, H., et al., "Remote ATtestation procedureS (RATS) Architecture", RFC 9334.
- **[RFC9711]** "The Entity Attestation Token (EAT)", RFC 9711.
- **[RFC9943]** SCITT, RFC 9943. `TODO(verify)`: title and authors.
- **[SD-JWT-VC]** IETF, "SD-JWT-based Verifiable Credentials", draft-ietf-oauth-sd-jwt-vc. `TODO(verify)`: revision number.
- **[TOIP-GMM]** Trust over IP Foundation, Governance Metamodel Specification.
- **[TRQP]** Trust over IP Foundation, "Trust Registry Query Protocol", v2.0.
- **[VC-DI-ECDSA]** W3C, "Data Integrity ECDSA Cryptosuites v1.0" (`ecdsa-jcs-2019`).
- **[VC-DI-EDDSA]** W3C, "Data Integrity EdDSA Cryptosuites v1.0" (`eddsa-jcs-2022`).
- **[VC-EXTENSIONS]** W3C, "Verifiable Credential Extensions" (note).
- **[VLEI-EGF]** GLEIF, vLEI Ecosystem Governance Framework v4.0.
- **[WEBBOTAUTH]** draft-ietf-webbotauth-httpsig-protocol-01.

---

## Appendix A. Failure Codes (informative)

Shared diagnostic codes help verifiers interoperate and make Groundmark easier to debug for the hosts who distribute it. They travel with the test vectors. A verifier SHOULD return one code per failure and keep cryptographic failures distinct from policy failures.

### A.1. Request

| Code | Meaning |
|---|---|
| `signature_input_invalid` | `Signature-Input` or `Signature` malformed, or a required component or parameter missing |
| `signature_expired` | `created` outside the window or `expires` passed |
| `keyid_unresolved` | `keyid` does not select exactly one usable `_agentid` record |
| `agentid_rrset_invalid` | Multiple records without distinct `kid=` |
| `dnssec_failure` | Any validation failure under Section 4.3 |
| `content_digest_mismatch` | Body does not match `content-digest` |
| `signature_invalid` | Signature does not verify |
| `nonce_missing` | State-changing profile and no nonce |
| `nonce_replayed` | Nonce already consumed |

### A.2. Presentation and Retrieval

| Code | Meaning |
|---|---|
| `groundmark_claim_missing` | Policy requires a credential and no `Groundmark-Claim` field is present |
| `groundmark_claim_duplicate` | More than one `Groundmark-Claim` field |
| `groundmark_claim_not_covered` | Field present but not covered by the signature |
| `idsp_record_missing` | No `_idsp` record for the agent domain |
| `reference_host_mismatch` | The reference's host is not named in `_idsp` (binding 4) |
| `fetch_rejected` | Fetch hardening rejected the reference or the response |
| `retrieval_failed` | The IDSP did not return a credential (404, 410, 401, 403, 406, timeout) |
| `groundmark_claim_policy_mismatch` | The presented claim is not the one policy requires |

### A.3. Credential

| Code | Meaning |
|---|---|
| `credential_malformed` | Not a valid SD-JWT or VCDM 2.0 credential |
| `credential_type_unrecognized` | Claim type unknown to the verifier |
| `credential_type_mismatch` | Credential type is not the presented `claim-type` |
| `schema_invalid` | `credentialSubject` fails the claim type's schema |
| `claim_subject_invalid` | `claim_subject` not permitted for the claim type |
| `evidence_missing` | `evidence` absent, empty or selectively disclosed |
| `issuer_key_unresolved` | `did:web` document or verification method not found |
| `issuer_key_dns_mismatch` | `did:web` key and `_agentid` key differ, or wrong purpose |
| `credential_signature_invalid` | JWS signature does not verify |
| `wrong_subject` | `agent_domain` is not the evaluated agent domain (binding 1) |
| `subject_key_mismatch` | `cnf.jkt` is not the request key's thumbprint (binding 2) |
| `issuer_not_named_in_dns` | `issuer` is not the IDSP named in `_idsp` (binding 3) |
| `credential_not_yet_valid` | `validFrom` in the future |
| `credential_expired` | `validUntil` passed |

### A.4. Status

| Code | Meaning |
|---|---|
| `status_unavailable` | Status list could not be fetched |
| `status_stale` | Status List Token past `exp` or `ttl` |
| `status_signature_invalid` | Status List Token signature or key check failed |
| `status_revoked` | `0x01`, or previously seen as revoked |
| `status_suspended` | `0x02` |
| `status_superseded` | `0x03` |

### A.5. Policy

| Code | Meaning |
|---|---|
| `issuer_untrusted` | No trusted anchor or local policy authorizes the IDSP |
| `issuer_key_untrusted` | The key is not authorized for this purpose |
| `framework_untrusted` | `framework` not accepted |
| `method_profile_untrusted` | Evidence profile or methods not accepted |
| `level_not_authorized` | `level` below the policy floor or above what the IDSP is accredited for |

---

## Appendix B. Informative Mapping to IETF SD-JWT VC

VCDM 2.0 secured as SD-JWT has few implementers in the W3C test reports, against a much larger population for IETF SD-JWT VC [SD-JWT-VC], which does not use the W3C data model. This mapping lets an IETF SD-JWT VC verifier read a Groundmark credential, and it should ship with version 1.

| Groundmark (VCDM 2.0) | SD-JWT VC |
|---|---|
| `type` (Groundmark credential type) | `vct` |
| `issuer` | `iss` |
| `validFrom`, `validUntil` | `nbf`, `exp` |
| `credentialSubject` claims | top-level claims |
| `evidence` | a claim named `evidence` with the same structure; SD-JWT VC defines no evidence construct |
| `cnf` | `cnf` |
| `status` | `status` |

`TODO(verify)`: each row against the current SD-JWT VC draft before publication.

---

## Appendix C. Disposition of the Earlier Texts

Map v1.0 sections 4, 6 and 9 hold the full table. In summary:

- **Kept as residue:** `_agentid` and its processing; DNSSEC resolver profile; RFC 9421 profile including nonce delivery in `Accept-Signature`; `Groundmark-Claim` syntax; `Groundmark-Accept`; reference hygiene; fetch hardening; claim subject; method execution fields; the four bindings; key rotation and identity reset; terminality of revocation; AAuth related work; failure codes, now informative.
- **Adopted:** payload format, signature and canonicalization (VCDM 2.0, SD-JWT); IDSP key publication (`did:web`, cross-checked); status (Token Status List); issuer authorization (TRQP); underscore label registration (RFC 8552); HTTP field registration (RFC 9110), both in the IETF -01.
- **New:** `_idsp`; self-issuance; the retrieval protocol and its gated mode; the release rule and disclosure record; the host check.
- **Moved:** levels and their fail modes, grace logging, governance and accreditation criteria, to the trust framework; `jurisdiction-licensed`, `kyc-basic`, `kyc-enhanced`, `brand-authorized` to the attestation library.
- **Deferred:** Method Receipts and IDTP receipt keys.
- **Dropped:** `_agentclaim` in all three forms; committed references and their digest; `endpoint_url`; `exp=` in DNS; I-JSON and JCS rules on the mandatory path; `pending_publication`, `expired` and `reason_code` on the wire; `operator-contact` and all self-asserted claims; the private pre-agent operator account; both IANA registries; the 1.0 to 1.1 migration text; registrant disclosure through RDAP as protocol; the pre-contact evaluation section and the principle that DNS is the single place a relying party consults.

---

## Appendix D. Items to Verify

Every `TODO(verify)` in this document:

1. JOSE `alg` value for Ed25519 in SD-JWT: `EdDSA` [RFC8037] or `Ed25519` [RFC9864] (Sections 8.6, 8.7).
2. JWS `typ` value required by VC-JOSE-COSE §3.2 (Section 8.7).
3. VCDM 2.0 section numbers §4.3, §4.4, §4.5 (contexts, identifiers, types), from memory in map v1.0 (Section 8.2), and §6.3 for type-specific processing (Section 8.1).
4. How Token Status List's `status` claim sits alongside VCDM 2.0 `credentialStatus` in a VC-JOSE-COSE credential (Section 8.2).
5. Whether Token Status List has an RFC number; pinned to -21 meanwhile (Section 12.1).
6. Groundmark `@context` URL, not yet published (Section 8.2).
7. Media type for the Data Integrity form (Section 7.1).
8. Web Bot Auth: Groundmark `tag` value, relationship to `Signature-Agent`, and §6.7 on request forgery, against -01 (Sections 5.7, 7.7).
9. OpenID4VP 1.0 §6 DCQL mapping for `Groundmark-Accept` (Section 6.2.4).
10. OpenID Federation §3 as the home of `authority_hints` (Section 20).
11. EUDI and ISO/IEC 18013-5 age attribute definitions; DIF Proof of Age title (Section 14.3).
12. Whether the W3C DID Methods WG has launched (reference [DID-WEB]).
13. What the production verifier and the live reference IDSP run today, schema 1.0 or 1.1 (Section 18).
14. That the IIW live path used open references (Section 18).
15. SD-JWT VC mapping rows and draft revision (Appendix B, [SD-JWT-VC]).
16. Full citations for RFC 9901, RFC 9864, RFC 9943, and the draft-ranjbar-dane-did revision (Section 21).
17. To test: that HAIP or FIDES verifiers accept an Ed25519 key in `cnf` (Section 8.6).
