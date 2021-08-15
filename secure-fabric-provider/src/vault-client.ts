import NodeVault, { client } from 'node-vault';
import { Logger } from 'winston';
import { getClassLogger, getMethodLogger, Options } from './util';
import { ec } from 'elliptic';
import { createPublicKey, JwkKeyExportOptions } from 'crypto';

const p256 = new ec('p256');
const p384 = new ec('p384');

enum supportedCurve {
  p256 = 'ecdsa-p256',
  p384 = 'ecdsa-p384',
}

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

// VaultTransitClient : transit engine client
// for sign , getPub , createKey
// TODO : verify , encrypt , decrypt
export class VaultTransitClient {
  private readonly classLogger: Logger;
  private readonly backend: client;
  constructor(opts: VaultTransitClientOptions) {
    this.classLogger = getClassLogger(opts.logLevel, 'VaultTransitClient');
    if (opts.endpoint === undefined || opts.endpoint === '') {
      throw new Error('require vault endpoint');
    }
    if (opts.mountPath === undefined || opts.mountPath === '') {
      throw new Error('require mount path of vault transit secret engine');
    }
    if (opts.token === undefined || opts.token === '') {
      throw new Error('require vault token');
    }
    this.backend = NodeVault({
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
    const methodLogger = getMethodLogger(this.classLogger, 'sign');
    methodLogger.debug(`sign with key = ${keyName} , digestSize = ${digest.length} , preHashed = ${preHashed}`);
    const resp = await this.backend.write('sign/' + keyName, {
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
   * @description return EC public key
   * @param keyName for which public key should be returned
   * @returns public key
   */
  async getPub(keyName: string): Promise<ec.KeyPair> {
    const methodLogger = getMethodLogger(this.classLogger, 'getPub');
    methodLogger.debug(`get ${keyName} key`);
    const resp = await this.backend.read('keys/' + keyName);
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
