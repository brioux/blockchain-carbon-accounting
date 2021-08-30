import { ICryptoKey } from 'fabric-common';

// internal class used by cryptoSuite, this is just to support interface provided by
// fabric-sdk-node
export class InternalKey implements ICryptoKey {
  getSKI(): string {
    throw new Error('not-required');
  }
  getHandle(): string {
    throw new Error('not-required');
  }
  isSymmetric(): boolean {
    throw new Error('not-required');
  }
  isPrivate(): boolean {
    throw new Error('not-required');
  }
  getPublicKey(): ICryptoKey {
    throw new Error('not-required');
  }
  toBytes(): string {
    throw new Error('not-required');
  }
}

import ecsig from 'elliptic/lib/elliptic/ec/signature.js';
import asn1 from 'asn1.js';
import BN from 'bn.js';
import { curves } from 'elliptic';

const EcdsaDerSig = asn1.define('ECPrivateKey', function () {
  return this.seq().obj(this.key('r').int(), this.key('s').int());
});

const p256N = (curves as any).p256.n as BN;
const p384N = (curves as any).p384.n as BN;

export function asn1ToDer(signature:Buffer,logger:any):Buffer{
  logger.debug(`converting asn1 sig format to der for fabric to accept`);
  const rsSig = EcdsaDerSig.decode(signature, 'der');
  const r = rsSig.r as BN;
  let s = rsSig.s as BN;
  if (r === undefined || s === undefined) {
    throw new Error('invalid signature');
  }
  let crvN: BN = p256N;
  if (this.crv === 'p384') {
    crvN = p384N;
  }
  const halfOrder = crvN.shrn(1);
  if (!halfOrder) {
    throw new Error('Can not find the half order needed to calculate "s" value for immalleable signatures');
  }
  if (s.cmp(halfOrder) === 1) {
    const bigNum = crvN as BN;
    s = bigNum.sub(s);
  }
  const der = new ecsig({ r: r, s: s }).toDER();
  logger.debug(`digest successfully signed`);
  return Buffer.from(der);
}
