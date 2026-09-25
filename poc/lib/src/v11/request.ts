import { verifyRequestUncommitted, commitRequestNonce, type VerifyRequestOptions } from '../verifyRequest.ts';
import { resolveClaims } from '../claim/resolveClaims.ts';
import { verifyAttestation11, Verification11Error, type Verify11Context } from './verify.ts';

export interface VerifyPresentedRequest11Options extends Omit<Verify11Context,'agentDomain'|'requestKey'|'claim'> {
  requestOptions: Omit<VerifyRequestOptions,'now'|'requireGroundmarkClaim'>;
}
/** Complete single-claim presentation verification. Consumes the nonce only after
 * request authentication, DNS reference binding, profile/issuer policy and status. */
export async function verifyPresentedRequest11(raw:Buffer,ctx:VerifyPresentedRequest11Options) {
  const request=await verifyRequestUncommitted(raw,ctx.resolver,{...ctx.requestOptions,now:ctx.now,requireGroundmarkClaim:true});
  if(!request.ok) throw new Verification11Error(request.reason);
  const presented=request.groundmarkClaim!;
  const claims=await resolveClaims(ctx.resolver,request.agentDomain);
  const matching=claims.filter(c=>c.kind==='ref' && c.claimType===presented.claimType && c.ref===presented.ref);
  if(matching.length!==1 || matching[0]!.kind!=='ref') throw new Verification11Error('groundmark_claim_dns_mismatch');
  const claim=matching[0]!;
  if(claim.exp!==undefined && (!Number.isFinite(Date.parse(claim.exp)) || Date.parse(claim.exp)/1000<=ctx.now)) throw new Verification11Error('claim_exp_passed');
  const attestation=await verifyAttestation11({...ctx,agentDomain:request.agentDomain,
    requestKey:{kid:request.kid ?? '',publicKey:request.publicKeyB64url},claim});
  const nonceFailure=await commitRequestNonce(request,ctx.requestOptions.nonceStore);
  if(nonceFailure) throw new Verification11Error(nonceFailure.reason);
  return {request,...attestation};
}
