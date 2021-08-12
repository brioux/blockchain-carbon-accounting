import { createPublicKey, JwkKeyExportOptions } from 'crypto';
import Vault, { client } from 'node-vault';
import { Logger } from 'winston';
import { Options, Util } from '../internal/util';
import { ec } from 'elliptic';

export interface VaultTransitClientOptions extends Options {
  // full url of vault server
  // eg : http://localhost:8200
  endpoint: string;

  // mountPath of transit secret engine
  // eg : /transit
  mountPath: string;

  // token of the client
  token: string;
}

enum supportedCurve {
  p256 = 'ecdsa-p256',
  p384 = 'ecdsa-p384',
}

const p256 = new ec('p256');
const p384 = new ec('p384');

// VaultTransitClient : transit engine client for
// - signing message digest
// - create new EC key with key size 256 and 384
// - rotate existing private key
// - get latest EC key
export class VaultTransitClient {
  private readonly classLogger: Logger;
  private readonly _backend: client;
  constructor(opts: VaultTransitClientOptions) {
    this.classLogger = Util.getClassLogger(opts.logLevel, 'VaultTransitClient');
    if (Util.isEmptyString(opts.endpoint)) {
      throw new Error('require vault endpoint');
    } else if (Util.isEmptyString(opts.mountPath)) {
      throw new Error('require transit engine mount path');
    } else if (Util.isEmptyString(opts.token)) {
      throw new Error('require vault token');
    }
    this._backend = Vault({
      endpoint: opts.endpoint,
      apiVersion: 'v1',
      token: opts.token,
      pathPrefix: opts.mountPath,
    });
  }

  /**
   * @description send message digest to be signed by private key stored on vault
   * @param digest : messages digest which need to signed
   * @param preHashed : is digest already hashed
   */
  async sign(keyName: string, digest: Buffer, preHashed: boolean): Promise<Buffer> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');
    methodLogger.debug(`sign with key = ${keyName} , digestSize = ${digest.length} , preHashed = ${preHashed}`);
    const resp = await this._backend.write('sign/' + keyName, {
      input: digest.toString('base64'),
      prehashed: preHashed,
      marshaling_algorithm: 'asn1',
    });
    methodLogger.debug(`got response from vault : %o`, resp.data);
    if (resp?.data?.signature) {
      const base64Sig = (resp.data.signature as string).split(':')[2];
      methodLogger.debug(`signature = ${base64Sig}`);
      return Buffer.from(base64Sig, 'base64');
    }
    throw new Error(`invalid response from vault ${JSON.stringify(resp)}`);
  }

  /**
   * @description will generate a EC private, new if key doesn't exists , and does nothing if key already exists
   * @param keyName label of the key
   * @param crv 'ecdsa-p256'|'ecdsa-p384'
   */
  async newKey(keyName: string, crv: 'ecdsa-p256' | 'ecdsa-p384'): Promise<void> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'newKey');
    methodLogger.debug(`generate new key with name = ${keyName} of type ${crv}`);
    await this._backend.write('keys/' + keyName, {
      type: crv,
    });
    methodLogger.debug(`key generated successfully`);
  }

  /**
   * @description will rotate a given key
   * @param keyName label of key that need to be rotated
   */
  async rotateKey(keyName: string) {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'rotateKey');
    methodLogger.debug(`rotate the kew ${keyName}`);
    await this._backend.write('keys/' + keyName + '/rotate', {});
    methodLogger.debug(`key successfully rotated`);
  }
  /**
   * @description return EC public key
   * @param keyName for which public key should be returned
   * @returns public key
   */
  async getPub(keyName: string): Promise<ec.KeyPair> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getPub');
    methodLogger.debug(`get ${keyName} key`);
    const resp = await this._backend.read('keys/' + keyName);
    methodLogger.debug(`got response from vault : %o`, resp.data);
    if (resp?.data?.latest_version && resp?.data?.keys) {
      let ecdsa: ec;
      switch (resp.data.type as string) {
        case supportedCurve.p256:
          ecdsa = p256;
          break;
        case supportedCurve.p384:
          ecdsa = p384;
          break;
        default:
          throw new Error(`only P-256 and P-384 curve are supported`);
      }
      const keyString = resp.data.keys[resp.data.latest_version].public_key as string;
      const pub = createPublicKey(keyString);
      const jwkExportOpts: JwkKeyExportOptions = {
        format: 'jwk',
      };
      const jwk = pub.export(jwkExportOpts);
      jwk.x = Buffer.from(jwk.x as string, 'base64').toString('hex');
      jwk.y = Buffer.from(jwk.y as string, 'base64').toString('hex');
      return ecdsa.keyFromPublic({
        x: jwk.x,
        y: jwk.y,
      });
    }
    throw new Error(`invalid response from vault ${JSON.stringify(resp)}`);
  }
}
