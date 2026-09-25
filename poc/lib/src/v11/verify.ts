/** Schema 1.1 verifier. No legacy fallback. Transport and authorization are explicit seams. */
import { createHash, type KeyObject } from "node:crypto";
import type { DnssecResolver } from "../dns/resolver.ts";
import type { HttpsFetcher } from "../attestation/fetcher.ts";
import { jcsBytes } from "../attestation/canonical.ts";
import { ed25519PublicKeyFromBase64url, verifyEd25519 } from "../crypto/ed25519.ts";
import { parseAgentIdRecord, assertMultiRecordValidity } from "../dns/agentidRecord.ts";
import { strictJson } from "./strictJson.ts";

export class Verification11Error extends Error {
  readonly reason: string;
  constructor(reason: string) {super(reason);this.reason=reason;this.name="Verification11Error";}
}
const fail=(reason:string): never => {throw new Verification11Error(reason);};
export type JsonObject=Record<string,unknown>;
export interface StatusObservation { sequence:number; digest:string; state:string; statusDigest:string; }
export interface StatusHistory {
  /** Atomic check-and-update; persist across process restarts in a relying party. */
  observe(issuer: string, attestationId: string, observation: StatusObservation): void;
}
/** Test/session implementation only. Applications supply durable atomic storage. */
export class MemoryStatusHistory implements StatusHistory {
  private readonly entries=new Map<string,StatusObservation>();
  observe(issuer:string,id:string,next:StatusObservation):void {
    const key=JSON.stringify([issuer,id]), old=this.entries.get(key);
    if(old) {
      if(old.digest !== next.digest) fail("attestation_identity_conflict");
      if(["revoked","superseded","expired"].includes(old.state) && next.state !== old.state) fail("status_terminal");
      if(next.sequence < old.sequence || (next.sequence === old.sequence && next.statusDigest !== old.statusDigest)) fail("status_replayed");
    }
    this.entries.set(key,{...next});
  }
}
export interface IssuerKey { idsp:string; kid:string; purpose:"attestation-signing"|"status-signing"; publicKey:string; thumbprint:string; }
export interface Verify11Context {
  agentDomain:string;
  /** From the exact key that verified the request, not from the fetched attestation. */
  requestKey:{kid:string;publicKey:string};
  claim:{claimType:string;idsp:string;ref:string};
  now:number; // UNIX seconds
  clockSkewSeconds?:number;
  resolver:DnssecResolver;
  /** Must enforce TLS, no redirects, SSRF controls, bounded reads and timeouts. */
  fetcher:HttpsFetcher;
  history:StatusHistory;
  /** Installed claim profile validates subject/value/level/methods; no profile means rejection. */
  validateProfile(payload:JsonObject): boolean;
  /** Explicit relying-party authorization, including claim/framework/jurisdiction/method/level. */
  authorize(key:IssuerKey,payload:JsonObject):boolean;
}
function string(o:JsonObject,k:string,empty=false):string {
  const v=o[k];if(typeof v !== "string" || (!empty && !v)) fail("attestation_malformed");return v as string;
}
function object(value:unknown):JsonObject {
  if(!value || typeof value !== "object" || Array.isArray(value)) return fail("attestation_malformed");return value as JsonObject;
}
function domain(v:string):void {
  if(v.length>253 || !v.includes('.') || !v.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))) fail("attestation_malformed");
}
function timestamp(o:JsonObject,k:string):number {
  const v=string(o,k);
  if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(v) || !Number.isFinite(Date.parse(v))) fail("attestation_malformed");
  return Date.parse(v)/1000;
}
function https(v:string):void {
  try {const u=new URL(v);if(u.protocol!=="https:" || u.username || u.password || u.hash || u.href!==v) fail("attestation_malformed");} catch {fail("attestation_malformed");}
}
function b64(v:string,len:number):Buffer {
  const bytes=Buffer.from(v,"base64url");if(bytes.length!==len || bytes.toString("base64url")!==v) fail("invalid_base64url");return bytes;
}
export const digest11=(v:Buffer):string=>"sha-256:"+createHash("sha256").update(v).digest("base64url");
export function keyThumbprint11(publicKey:string):string {
  b64(publicKey,32);return createHash("sha256").update(jcsBytes({crv:"Ed25519",kty:"OKP",x:publicKey})).digest("base64url");
}
async function key(ctx:Verify11Context,idsp:string,kid:string,purpose:IssuerKey["purpose"]):Promise<{info:IssuerKey;key:KeyObject}> {
  const answer=await ctx.resolver.resolveTxt(`_agentid.${idsp}`);
  if(answer.status!=="secure") return fail("idsp_dnssec_validation_failed");
  let parsed;
  try {parsed=answer.records.map(parseAgentIdRecord);assertMultiRecordValidity(parsed);} catch {return fail("idsp_key_unresolved");}
  const selected=parsed.find(r=>r.kid===kid && r.purpose===purpose);
  if(!selected || selected.alg!=="ed25519") return fail("signing_key_purpose_no_match");
  b64(selected.publicKeyB64url,32);
  return {info:{idsp,kid,purpose,publicKey:selected.publicKeyB64url,thumbprint:keyThumbprint11(selected.publicKeyB64url)},key:ed25519PublicKeyFromBase64url(selected.publicKeyB64url)};
}
function signature(payload:JsonObject,key:KeyObject,reason:string):void {
  const {signature,...unsigned}=payload;
  if(typeof signature!=="string") fail(reason);
  try {if(!verifyEd25519(key,jcsBytes(unsigned),b64(signature as string,64))) fail(reason);} catch {fail(reason);}
}
async function fetchJson(ctx:Verify11Context,url:string):Promise<JsonObject> {
  https(url);
  try {
    const res=await ctx.fetcher.get(url);
    if(res.status!==200 || res.contentType?.split(';')[0]?.trim().toLowerCase()!=="application/json") fail("fetch_failed");
    return strictJson(res.body);
  } catch(e) {if(e instanceof Verification11Error) throw e;return fail("fetch_or_json_failed");}
}
function shape(a:JsonObject,now:number):void {
  if(a.schema_version!=="1.1") fail("unknown_schema_version");
  for(const k of ["attestation_id","subject","claim_type","idsp","endpoint_url","status_url","signing_key_id","signature"]) string(a,k);
  string(a,"subject_key_id",true); b64(string(a,"subject_key_thumbprint"),32);
  if("revocation_endpoint" in a || "short_lived_token" in a) fail("attestation_malformed");
  domain(string(a,"subject"));domain(string(a,"idsp"));https(string(a,"endpoint_url"));https(string(a,"status_url"));
  if(!Number.isInteger(a.level) || (a.level as number)<0 || (a.level as number)>3) fail("attestation_malformed");
  object(a.claim_value);const subject=object(a.claim_subject);
  if(!["agent","operator","authorized-human","beneficiary","intended-recipient"].includes(string(subject,"role")) ||
     !["organization","natural-person","software-agent","other"].includes(string(subject,"entity_type"))) fail("attestation_malformed");
  string(subject,"relationship");
  const md=object(a.method_disclosure);string(md,"profile");string(md,"profile_version");
  if(!Array.isArray(md.executions) || ((a.level as number)>0 && md.executions.length===0)) fail("attestation_malformed");
  for(const raw of md.executions as unknown[]) {
    const e=object(raw);string(e,"method_id");string(e,"method_version");
    if(!["idsp-direct","idsp-operated-technology","authoritative-source-query","idtp-managed-service"].includes(string(e,"execution_mode"))) fail("attestation_malformed");
    const performer=object(e.performed_by);string(performer,"role");domain(string(performer,"domain"));
    const performed=timestamp(e,"performed_at");
    if(performed>timestamp(a,"issued_at")) fail("method_execution_invalid");
    if(e.valid_until!==undefined && timestamp(e,"valid_until")<=timestamp(a,"issued_at")) fail("method_execution_invalid");
    if(e.execution_mode!=="idtp-managed-service" && (performer.domain!==a.idsp || performer.role!=="idsp")) fail("method_execution_invalid");
    if(e.execution_mode==="idsp-operated-technology") domain(string(object(e.provider),"domain"));
    if(e.execution_mode==="authoritative-source-query") {string(e,"source_class");domain(string(e,"source_domain"));if(timestamp(e,"source_observed_at")>performed) fail("method_execution_invalid");}
    if(e.execution_mode==="idtp-managed-service" && !/^sha-256:[A-Za-z0-9_-]{43}$/.test(string(e,"receipt_digest"))) fail("method_execution_invalid");
  }
}
/** Verifies both immutable attestation and fresh signed status against explicit bindings and policy. */
export async function verifyAttestation11(ctx:Verify11Context):Promise<{payload:JsonObject;status:JsonObject;attestationKey:IssuerKey;statusKey:IssuerKey}> {
  domain(ctx.agentDomain);domain(ctx.claim.idsp);
  if(!Number.isFinite(ctx.now) || !Number.isFinite(ctx.clockSkewSeconds ?? 0) || (ctx.clockSkewSeconds ?? 0)<0) fail("invalid_verification_context");
  const a=await fetchJson(ctx,ctx.claim.ref);shape(a,ctx.now);
  if(a.subject!==ctx.agentDomain) fail("wrong_subject");
  if(a.endpoint_url!==ctx.claim.ref) fail("endpoint_mismatch");
  if(a.claim_type!==ctx.claim.claimType) fail("attestation_claim_type_mismatch");
  if(a.idsp!==ctx.claim.idsp) fail("attestation_idsp_mismatch");
  if(a.subject_key_id!==ctx.requestKey.kid) fail("subject_key_id_mismatch");
  if(a.subject_key_thumbprint!==keyThumbprint11(ctx.requestKey.publicKey)) fail("subject_key_mismatch");
  const issued=timestamp(a,"issued_at"),expires=timestamp(a,"expires_at");
  if(issued>ctx.now+(ctx.clockSkewSeconds ?? 0)) fail("attestation_not_yet_valid");
  if(expires<=ctx.now || expires<=issued) fail("attestation_expired");
  const ak=await key(ctx,string(a,"idsp"),string(a,"signing_key_id"),"attestation-signing");
  signature(a,ak.key,"attestation_signature_invalid");
  if(!ctx.validateProfile(a)) fail("claim_profile_rejected");
  if(!ctx.authorize(ak.info,a)) fail("issuer_key_untrusted");
  const s=await fetchJson(ctx,string(a,"status_url"));
  if(s.schema_version!=="1.0") fail("status_schema_invalid");
  if(s.attestation_id!==a.attestation_id || s.attestation_digest!==digest11(jcsBytes(a))) fail("status_binding_mismatch");
  if(!Number.isSafeInteger(s.sequence) || (s.sequence as number)<1 || !["pending_publication","active","suspended","revoked","superseded","expired"].includes(string(s,"status"))) fail("status_malformed");
  if(s.reason_code!==null && typeof s.reason_code!=="string") fail("status_malformed");
  const thisUpdate=timestamp(s,"this_update"),nextUpdate=timestamp(s,"next_update");
  if(thisUpdate>ctx.now+(ctx.clockSkewSeconds ?? 0) || thisUpdate<issued || nextUpdate<=thisUpdate) fail("status_time_invalid");
  if(nextUpdate<=ctx.now) fail("status_stale");
  const sk=await key(ctx,string(a,"idsp"),string(s,"signing_key_id"),"status-signing");
  if(sk.info.publicKey===ak.info.publicKey) fail("signing_key_purpose_reuse");
  signature(s,sk.key,"status_signature_invalid");
  if(!ctx.authorize(sk.info,a)) fail("issuer_key_untrusted");
  ctx.history.observe(string(a,"idsp"),string(a,"attestation_id"),{sequence:s.sequence as number,digest:string(s,"attestation_digest"),state:string(s,"status"),statusDigest:digest11(jcsBytes(s))});
  if(s.status!=="active") fail("status_not_active");
  return {payload:a,status:s,attestationKey:ak.info,statusKey:sk.info};
}
