import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { jcsBytes } from '../src/attestation/canonical.ts';
import { MockDnssecResolver } from '../src/dns/mockResolver.ts';
import { MockHttpsFetcher } from '../src/attestation/fetcher.ts';
import { verifyAttestation11, Verification11Error, MemoryStatusHistory, digest11, type Verify11Context } from '../src/v11/verify.ts';
import { strictJson } from '../src/v11/strictJson.ts';
const dir=new URL('./fixtures/m3-v11/',import.meta.url);
const read=(name:string)=>readFileSync(new URL(name,dir));
const json=(name:string)=>JSON.parse(read(name).toString());
const manifest=json('manifest.json');
const seed=Buffer.alloc(32,17);
const privateKey=(bytes:Buffer)=>createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),bytes]),format:'der',type:'pkcs8'});
function signed(value:Record<string,unknown>,bytes=seed) {
  const {signature,...unsigned}=value;
  return {...unsigned,signature:sign(null,jcsBytes(unsigned),privateKey(bytes)).toString('base64url')};
}
function setup(claim='operator-verified') {
  const att=json(`attestation-${claim}.json`), status=json(`status-${claim}-active.json`);
  const records=manifest.keys.map((k:any)=>`v=gm1; k=ed25519; p=${k.public_key}; kid=${k.signing_key_id}; purpose=${k.purpose}`);
  const resolver=new MockDnssecResolver().setSecure('_agentid.trustedweb.com',{records});
  const fetcher=new MockHttpsFetcher().setRaw(att.endpoint_url,read(`attestation-${claim}.json`),{contentType:'application/json'}).setJson(att.status_url,status);
  const ctx:Verify11Context={agentDomain:att.subject,requestKey:{kid:'',publicKey:manifest.subject_key.public_key},
    claim:{claimType:claim,idsp:att.idsp,ref:att.endpoint_url},now:Date.parse('2026-07-16T00:01:00Z')/1000,
    resolver,fetcher,history:new MemoryStatusHistory(),
    validateProfile:a=>a.claim_type===claim && (a.method_disclosure as any).profile==='retail-simulation',
    authorize:k=>k.idsp==='trustedweb.com' && ['k1','s1','s2'].includes(k.kid)};
  return {ctx,att,status,records,resolver,fetcher};
}
const rejects=(promise:Promise<unknown>,reason:string)=>assert.rejects(promise,(e:unknown)=>e instanceof Verification11Error && e.reason===reason);

test('both issuer-generated 1.1 vectors verify byte-for-byte with purpose-scoped DNS keys',async()=>{
  for(const claim of ['operator-verified','age-over-21']) {
    const h=setup(claim);const result=await verifyAttestation11(h.ctx);
    assert.equal(result.status.status,'active');
    assert.equal(digest11(jcsBytes(result.payload)),manifest.vectors.find((v:any)=>v.claim_type===claim).canonical_digest);
    assert.deepEqual(jcsBytes(result.payload),read(`attestation-${claim}.json`));
    const {signature,...unsigned}=result.payload;
    assert.deepEqual(jcsBytes(unsigned),read(`unsigned-${claim}.json`));
    assert.notEqual(result.attestationKey.publicKey,result.statusKey.publicKey);
  }
});
test('binds the exact request key, subject, DNS issuer, claim and reference',async()=>{
  const cases: Array<[string,(h:ReturnType<typeof setup>)=>void]>=[
    ['subject_key_id_mismatch',h=>{h.ctx.requestKey.kid='wrong';}],
    ['subject_key_mismatch',h=>{h.ctx.requestKey.publicKey=manifest.keys[0].public_key;}],
    ['wrong_subject',h=>{h.ctx.agentDomain='other.example';}],
    ['attestation_claim_type_mismatch',h=>{h.ctx.claim.claimType='age-over-21';}],
    ['attestation_idsp_mismatch',h=>{h.ctx.claim.idsp='other.example';}],
    ['endpoint_mismatch',h=>{h.ctx.claim.ref='https://attestations.trustedweb.com/a/different';h.fetcher.setJson(h.ctx.claim.ref,h.att);}],
  ];
  for(const [reason,alter] of cases) {const h=setup();alter(h);await rejects(verifyAttestation11(h.ctx),reason);}
});
test('requires secure DNS, exact purpose, installed claim profile and explicit key authorization',async()=>{
  let h=setup();h.resolver.setFailure('_agentid.trustedweb.com','insecure');await rejects(verifyAttestation11(h.ctx),'idsp_dnssec_validation_failed');
  h=setup();h.resolver.setSecure('_agentid.trustedweb.com',{records:h.records.map((r:string)=>r.replace('purpose=status-signing','purpose=attestation-signing'))});await rejects(verifyAttestation11(h.ctx),'signing_key_purpose_no_match');
  h=setup();h.ctx.validateProfile=()=>false;await rejects(verifyAttestation11(h.ctx),'claim_profile_rejected');
  h=setup();h.ctx.authorize=()=>false;await rejects(verifyAttestation11(h.ctx),'issuer_key_untrusted');
});
test('rejects stale, unsigned, wrong-digest and non-active status',async()=>{
  let h=setup();h.ctx.now+=300;await rejects(verifyAttestation11(h.ctx),'status_stale');
  h=setup();h.fetcher.setJson(h.att.status_url,{...h.status,signature:'bad'});await rejects(verifyAttestation11(h.ctx),'status_signature_invalid');
  h=setup();h.fetcher.setJson(h.att.status_url,{...h.status,attestation_digest:'sha-256:wrong'});await rejects(verifyAttestation11(h.ctx),'status_binding_mismatch');
  h=setup();h.fetcher.setJson(h.att.status_url,json('status-operator-verified-pending.json'));await rejects(verifyAttestation11(h.ctx),'status_not_active');
});
test('sequence high-water survives key rotation and rejects same-sequence divergent objects',async()=>{
  const h=setup();await verifyAttestation11(h.ctx);
  const rotatedSeed=Buffer.alloc(32,19);
  const pub=createPublicKey(privateKey(rotatedSeed)).export({format:'jwk'}).x!;
  h.resolver.setSecure('_agentid.trustedweb.com',{records:[...h.records,`v=gm1; k=ed25519; p=${pub}; kid=s2; purpose=status-signing`]});
  h.fetcher.setJson(h.att.status_url,signed({...h.status,signing_key_id:'s2',sequence:3},rotatedSeed));
  await verifyAttestation11(h.ctx);
  h.fetcher.setJson(h.att.status_url,h.status);await rejects(verifyAttestation11(h.ctx),'status_replayed');
  h.fetcher.setJson(h.att.status_url,signed({...h.status,signing_key_id:'s2',sequence:3,reason_code:'changed'},rotatedSeed));
  await rejects(verifyAttestation11(h.ctx),'status_replayed');
});
test('terminality cannot be reversed by a fresh higher-sequence signature',async()=>{
  const h=setup();await verifyAttestation11(h.ctx);
  h.fetcher.setJson(h.att.status_url,json('status-operator-verified-revoked.json'));
  await rejects(verifyAttestation11(h.ctx),'status_not_active');
  h.fetcher.setJson(h.att.status_url,signed({...h.status,sequence:4}));
  await rejects(verifyAttestation11(h.ctx),'status_terminal');
});
test('another authenticated issuer copying an ID cannot poison the first issuer',async()=>{
  const h=setup();await verifyAttestation11(h.ctx);
  const attSeed=Buffer.from('Zgdt2Jjlbxv95gfObZtUNLJeLRbJjC--jdFcQW4_mXo','base64url');
  const otherAtt=structuredClone(h.att);otherAtt.idsp='other.example';
  for(const e of otherAtt.method_disclosure.executions) e.performed_by.domain='other.example';
  otherAtt.endpoint_url='https://other.example/a/other';otherAtt.status_url='https://other.example/s/other';
  const att=signed(otherAtt,attSeed);
  const revoked=signed({...json('status-operator-verified-revoked.json'),attestation_digest:digest11(jcsBytes(att))});
  h.resolver.setSecure('_agentid.other.example',{records:h.records});
  h.fetcher.setJson(otherAtt.endpoint_url,att).setJson(otherAtt.status_url,revoked);
  const other={...h.ctx,claim:{claimType:'operator-verified',idsp:'other.example',ref:otherAtt.endpoint_url},authorize:()=>true};
  await rejects(verifyAttestation11(other),'status_not_active');
  await verifyAttestation11(h.ctx);
});
test('unauthorized status cannot poison terminality history',async()=>{
  const h=setup();h.fetcher.setJson(h.att.status_url,json('status-operator-verified-revoked.json'));
  h.ctx.authorize=k=>k.purpose==='attestation-signing';await rejects(verifyAttestation11(h.ctx),'issuer_key_untrusted');
  h.ctx.authorize=()=>true;h.fetcher.setJson(h.att.status_url,h.status);await verifyAttestation11(h.ctx);
});
test('strict parsing rejects duplicate escaped keys, unsafe numbers, invalid UTF8 and lone surrogates',()=>{
  for(const body of [Buffer.from('{"x":1,"\\u0078":2}'),Buffer.from('{"nested":{"x":1,"x":2}}'),Buffer.from('{"x":1e999}'),Buffer.from('{"x":9007199254740993}'),Buffer.from('{"x":"\\ud800"}'),Buffer.from([123,34,120,34,58,34,255,34,125])]) assert.throws(()=>strictJson(body));
});
test('origin failure, redirects and attestation expiry fail closed',async()=>{
  let h=setup();h.fetcher.setUnreachable(h.att.status_url);await rejects(verifyAttestation11(h.ctx),'fetch_or_json_failed');
  h=setup();h.fetcher.setJson(h.att.endpoint_url,h.att,{status:302});await rejects(verifyAttestation11(h.ctx),'fetch_failed');
  h=setup();h.ctx.now=Date.parse(h.att.expires_at)/1000;await rejects(verifyAttestation11(h.ctx),'attestation_expired');
});

test('signed presentation binds the actual request key and consumes nonce only after policy',async()=>{
  const { verifyPresentedRequest11 }=await import('../src/v11/request.ts');
  const h=setup();
  h.resolver.setSecure(`_agentid.${h.att.subject}`,{records:[`v=gm1; k=ed25519; p=${manifest.subject_key.public_key}`]});
  h.resolver.setSecure(`_agentclaim.${h.att.subject}`,{records:[`v=gm1; claim=operator-verified; idsp=trustedweb.com; ref=${h.att.endpoint_url}; exp=2026-12-01`]});
  const header=`claim-type="operator-verified"; ref="${h.att.endpoint_url}"`;
  const params=`("@method" "@authority" "@target-uri" "groundmark-claim");created=${h.ctx.now};keyid="${h.att.subject}";alg="ed25519";nonce="v11-test"`;
  const base=`"@method": GET\n"@authority": relying.example\n"@target-uri": https://relying.example/check\n"groundmark-claim": ${header}\n"@signature-params": ${params}`;
  const sig=sign(null,Buffer.from(base),privateKey(Buffer.from('yZa0s0viLdgl9BMTMXJiwEheURaJkfSXVaNYokUOuO4','base64url'))).toString('base64');
  const raw=Buffer.from(`GET /check HTTP/1.1\r\nHost: relying.example\r\nGroundmark-Claim: ${header}\r\nSignature-Input: gm=${params}\r\nSignature: gm=:${sig}:\r\n\r\n`);
  let consumed=false;
  const options={...h.ctx,requestOptions:{requireNonce:true,nonceStore:{consumeOnce:async()=>{if(consumed)return false;consumed=true;return true;}}}};
  await rejects(verifyPresentedRequest11(raw,{...options,authorize:()=>false}),'issuer_key_untrusted');
  assert.equal(consumed,false);
  const result=await verifyPresentedRequest11(raw,options);
  assert.equal(result.request.publicKeyB64url,manifest.subject_key.public_key);assert.equal(consumed,true);
  await rejects(verifyPresentedRequest11(raw,options),'nonce_replayed');
});

test('same-day duration uses a date upper bound while signed expiry stays exact',async()=>{
  const { verifyPresentedRequest11 }=await import('../src/v11/request.ts');
  const h=setup();
  const start=Date.parse('2026-07-16T14:00:00Z')/1000;
  const attSeed=Buffer.from('Zgdt2Jjlbxv95gfObZtUNLJeLRbJjC--jdFcQW4_mXo','base64url');
  const att=signed({...h.att,issued_at:'2026-07-16T14:00:00Z',expires_at:'2026-07-16T14:05:00Z'},attSeed);
  h.fetcher.setJson(h.att.endpoint_url,att);
  h.fetcher.setJson(h.att.status_url,signed({...h.status,attestation_digest:digest11(jcsBytes(att)),
    this_update:'2026-07-16T14:00:00Z',next_update:'2026-07-16T14:05:00Z'}));
  h.resolver.setSecure(`_agentid.${h.att.subject}`,{records:[`v=gm1; k=ed25519; p=${manifest.subject_key.public_key}`]});
  const dns=(exp:string)=>h.resolver.setSecure(`_agentclaim.${h.att.subject}`,{records:[`v=gm1; claim=operator-verified; idsp=trustedweb.com; ref=${h.att.endpoint_url}; exp=${exp}`]});
  const header=`claim-type="operator-verified"; ref="${h.att.endpoint_url}"`;
  const raw=(now:number)=>{
    const params=`("@method" "@authority" "@target-uri" "groundmark-claim");created=${now};keyid="${h.att.subject}";alg="ed25519"`;
    const base=`"@method": GET\n"@authority": relying.example\n"@target-uri": https://relying.example/check\n"groundmark-claim": ${header}\n"@signature-params": ${params}`;
    const signature=sign(null,Buffer.from(base),privateKey(Buffer.from('yZa0s0viLdgl9BMTMXJiwEheURaJkfSXVaNYokUOuO4','base64url'))).toString('base64');
    return Buffer.from(`GET /check HTTP/1.1\r\nHost: relying.example\r\nGroundmark-Claim: ${header}\r\nSignature-Input: gm=${params}\r\nSignature: gm=:${signature}:\r\n\r\n`);
  };
  dns('2026-07-16');
  await rejects(verifyPresentedRequest11(raw(start+60),{...h.ctx,now:start+60,requestOptions:{}}),'claim_exp_passed');
  dns('2026-07-17');
  await verifyPresentedRequest11(raw(start+299),{...h.ctx,now:start+299,requestOptions:{}});
  for(const now of [start+300,start+301])
    await rejects(verifyPresentedRequest11(raw(now),{...h.ctx,now,requestOptions:{}}),'attestation_expired');
});
