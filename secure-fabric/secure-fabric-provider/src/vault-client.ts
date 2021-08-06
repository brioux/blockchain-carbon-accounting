// vault-client.ts : for interacting with vault transit engine
import { getClassLogger, getMethodLogger, options } from './util';
import { Logger } from 'winston';
import NodeVault, { client } from 'node-vault';
import { JsonWebKey, createPublicKey, JwkKeyExportOptions } from 'crypto';
export interface VaultTransitClientOptions extends options {
  // endpoint should be full url
  // eg : http://localhost:8200
  endpoint: string;
  // mount path : /transit
  mountPath: string;
}

enum ECCrvType {
  P256 = 'p256',
  P384 = 'p384',
}

interface ECJWK {
  crv: ECCrvType;
  // hex encoded
  x: string;
  y: string;
}

// VaultTransitClient : transit engine client
// for signing , verifying , encrypting , decrypting , getPublic key
// TODO : verify , encrypt , decrypt
export class VaultTransitClient {
  private readonly classLogger: Logger;
  private readonly endpoint: string;
  private readonly mountPath: string;
  constructor(opt: VaultTransitClientOptions) {
    this.classLogger = getClassLogger(opt.logLevel, 'VaultTransitClient');
    this.endpoint = opt.endpoint;
    this.mountPath = opt.mountPath;
  }

  /**
   * @description send message digest to be signed by private key stored on vault
   * @param token for authentication with vault
   * @param keyName : name of signing key
   * @param digest : messages digest which need to signed
   * @param preHashed : is digest already hashed
   * @returns asn1 encoded signature
   */
  async sign(token: string, keyName: string, digest: Buffer, preHashed: boolean): Promise<Buffer> {
    const methodLogger = getMethodLogger(this.classLogger, 'sign');
    methodLogger.debug(`keyName = ${keyName} , preHashed = ${preHashed} , digestSize = ${digest.length}`);
    const backend = this._getBackend(token);
    let resp: any;
    try {
      resp = await backend.write('sign/' + keyName, {
        input: digest.toString('base64'),
        prehashed: preHashed,
        marshaling_algorithm: 'asn1',
      });
    } catch (error) {
      throw error;
    }
    methodLogger.debug(`got response from vault : %o`, resp.data);
    if (resp?.data?.signature) {
      // resp.data.signature = vault:vx:base64EncodedASN1
      const base64Sig = (resp.data.signature as string).split(':')[2];
      methodLogger.debug(`signature = ${base64Sig}`);
      return Buffer.from(base64Sig);
    } else {
      throw new Error(`invalid response from vault ${JSON.stringify(resp)}`);
    }
  }

  /**
   * @description return EC public key
   * @param token of client
   * @param keyName for which public key should be returned
   * @returns JWK with x and y point hex encoded
   */
  async getPub(token: string, keyName: string): Promise<ECJWK> {
    const methodLogger = getMethodLogger(this.classLogger, 'getPub');
    methodLogger.debug(`keyName = ${keyName}`);
    const backend = this._getBackend(token);
    const resp = await backend.read('keys/' + keyName);
    methodLogger.debug(`got response from vault : %o`, resp.data);
    if (resp?.data?.latest_version && resp?.data?.keys) {
      let crv: ECCrvType;
      switch (resp.data.type as string) {
        case 'ecdsa-p256':
          crv = ECCrvType.P256;
          break;
        case 'ecdsa-p384':
          crv = ECCrvType.P384;
          break;
        default:
          throw new Error(`only P-256 and P-384 curve are supported, but provided ${resp.data.type}`);
      }
      const keyString = resp.data.keys[resp.data.latest_version].public_key as string;
      const pub = createPublicKey(keyString);
      const jwkExportOpts: JwkKeyExportOptions = {
        format: 'jwk',
      };
      const jwk = pub.export(jwkExportOpts);
      methodLogger.debug(`pubKey = %o`, jwk);
      return {
        x: Buffer.from(jwk.x as string, 'base64').toString('hex'),
        y: Buffer.from(jwk.y as string, 'base64').toString('hex'),
        crv: crv,
      };
    }
    throw new Error(`invalid response from vault ${JSON.stringify(resp)}`);
  }
  private _getBackend(token: string): client {
    return NodeVault({
      apiVersion: 'v1',
      endpoint: this.endpoint,
      pathPrefix: this.mountPath,
      token: token,
    });
  }
}
