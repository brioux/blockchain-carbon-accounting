import {
  Logger,
  LoggerProvider,
  LogLevelDesc,
} from "@hyperledger/cactus-common";
import WebSocket from "ws";
import { KJUR } from "jsrsasign";
import { InternalIdentityClient, ISignatureResponse } from "../internal/client";
import { ECCurveType, CryptoUtil } from "../internal/crypto-util";

export interface WSClientOptions {
  // short name for ecdsa curve used by external client
  curve: ECCurveType;
  // web socket used to communicate with external client
  webSocket: WebSocket;
  // public key hex operated by external client
  pubKeyHex: string;
  // Ecdsa object from jsrsasign package used in the getPub method
  // Built before creating a new client to verify the incoming webSocket connection
  pubKeyEcdsa: KJUR.crypto.ECDSA;
  logLevel?: LogLevelDesc;
}

interface IDigestQueue {
  digest: Buffer;
  signature: Buffer;
}

export class WebSocketClient implements InternalIdentityClient {
  public readonly className = "WebSocketClient";
  private readonly log: Logger;
  webSocket: WebSocket;
  private readonly curve: ECCurveType;
  private readonly pubKeyEcdsa: KJUR.crypto.ECDSA; //KJUR.crypto.ECDSA for csr requests;
  readonly pubKeyHex: string;
  digestQueue: IDigestQueue[] = []; // Array of Digests to queue signing requests in series
  readonly keyName: string;

  constructor(opts: WSClientOptions) {
    this.log = LoggerProvider.getOrCreate({
      label: "WebSocketClient",
      level: opts.logLevel || "INFO",
    });
    this.webSocket = opts.webSocket;
    this.curve = opts.curve;
    this.pubKeyHex = opts.pubKeyHex;
    this.pubKeyEcdsa = opts.pubKeyEcdsa;
    this.keyName = `${this.pubKeyHex.substring(0, 12)}...`;
    this.digestQueue = [];

    const { pubKeyHex, pubKeyEcdsa, digestQueue, webSocket, log } = this;
    this.webSocket.on("message", function incoming(signature: Buffer) {
      const queueI = digestQueue.length;
      log.debug(
        `append signature to digestQueue index ${queueI} and mark as processed`,
      );
      const digest = digestQueue[queueI - 1].digest;
      digestQueue[queueI - 1].signature = Buffer.from(signature);

      const verified = pubKeyEcdsa.verifyHex(
        digest.toString("hex"),
        signature.toString("hex"),
        pubKeyHex,
      );
      if (!verified) {
        const err = `signature for digest queue ${queueI} does not match the public key`;
        log.error(err);
        webSocket.close();
        throw new Error(err);
      }
    });
  }

  /**
   * @description : sign message and return in a format that fabric understand
   * @param keyName : required by the sign method of abstract InternalIdentityClient
   * serves no role in the web-socket communication
   * the client only knows that a web-socket connection has been established
   * for a unique sessionId assigned to a given public key
   * @param digest to be singed
   */
  async sign(keyName: string, digest: Buffer): Promise<ISignatureResponse> {
    const fnTag = `${this.className}#sign`;
    this.log.debug(
      `${fnTag} send digest for pub-key ${this.keyName}: digest-size = ${digest.length}`,
    );
    let queueI = this.digestQueue.length - 1; //spot in the digest queue
    if (
      queueI >= 0 &&
      this.digestQueue[queueI].signature.toString().length == 0
    ) {
      // TO DO: enable parallel signature processing?
      throw new Error("waiting for a previous digest signature");
    }
    this.digestQueue.push({ digest: digest, signature: Buffer.from("") });
    this.webSocket.send(digest);

    queueI = this.digestQueue.length;
    this.log.debug(`${fnTag} wait for digest ${queueI} to be signed`);
    queueI -= 1;
    const raw = await inDigestQueue(this, queueI);
    const sig = CryptoUtil.encodeASN1Sig(raw, this.curve);
    return { sig, crv: this.curve };
  }

  /**
   * @description return the pre-built ECDSA public key object
   */
  async getPub(keyName: string): Promise<KJUR.crypto.ECDSA> {
    const fnTag = `${this.className}#get-pub`;
    const { pubKeyEcdsa } = this;
    this.log.debug(
      `${fnTag} return the ECDSA public key of the connected web-socket-client. ${keyName} is required in the abstract implementation but not used here`,
    );
    return new Promise(function (resolve) {
      resolve(pubKeyEcdsa);
    });
  }
  /**
   * @description Rotate public used by client with keyName
   * this method is inactive when using a web-socket client
   * not authorized to request or change external keys
   */
  async rotateKey(keyName: string): Promise<void> {
    const fnTag = `${this.className}#rotate-key`;
    this.log.debug(
      `${fnTag} inactive method for ${this.className}, provide key-name ${keyName} as abstract interface requirement`,
    );
    return new Promise(function (resolve, reject) {
      reject(
        "web-socket client can not rotate private keys. External client must enroll with a new csr",
      );
    });
  }
  public close() {
    this.webSocket.close();
  }
}
/**
 * @description : wait for digest in queue to be processed
 * @param index
 * @return signature as Buffer
 */
function inDigestQueue(
  client: WebSocketClient,
  queueI: number,
): Promise<Buffer> {
  return new Promise(function (resolve) {
    setTimeout(function () {
      if (client.digestQueue[queueI].signature.toString().length > 0) {
        resolve(client.digestQueue[queueI].signature);
      } else {
        inDigestQueue(client, queueI).then(resolve);
      }
    });
  });
}
