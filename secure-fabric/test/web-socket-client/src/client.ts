import WebSocket from "ws";
import fs from "fs";
import elliptic from "elliptic";
import {
  keyGen,
  getKeyPath,
  IClientNewKey,
  KeyData,
  ECCurveType,
} from "./key";
import {
  Logger,
  Checks,
  LogLevelDesc,
  LoggerProvider,
} from "@hyperledger/cactus-common";

interface WSClientOptions {
  host: string;
  keyName?: string;
  curve?: ECCurveType;
  logLevel?: LogLevelDesc;
}

export class WebSocketClient {
  public readonly className = "WebSocketClient";
  private readonly log: Logger;
  private readonly host: string;
  private ecdsaCurves: IEcdsaCurves;
  private keyName: string;
  private keyData: KeyData;
  private ws?: WebSocket;

  constructor(opts: WSClientOptions) {
    const fnTag = `${this.className}#constructor()`;
    Checks.truthy(opts, `${fnTag} arg options`);
    this.log = LoggerProvider.getOrCreate({
      label: "WebSocketClient",
      level: opts.logLevel || "INFO",
    });
    Checks.nonBlankString(opts.host, `${this.className}:opts.host`);
    this.host = opts.host;
    opts.keyName = opts.keyName || "default";
    this.keyData = this.initKey({ keyName: opts.keyName, curve: opts.curve });
  }

  /**
   * @description will generate a new EC private key, or get existing key it already exists
   * @param args;
   * @type IClientNewKey
   */
  private initKey(args: IClientNewKey): KeyData {
    const fnTag = `${this.className}#initKey`;
    this.log.debug(
      `${fnTag} look for key with name '${args.keyName}' or generate new key`,
    );
    const info = [];
    const keyPath = getKeyPath(args.keyName);
    if (!fs.existsSync(keyPath)) {
      info.push(keyGen(args));
    }
    info.push(`extracting key '${args.keyName}' from key store`);
    this.keyName = args.keyName;
    const keyData = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    const curve = keyData.curve;
    if (args.curve && curve !== args.curve) {
      info.push(
        `the requested curve type (${args.curve}) is different than the existing key: ${curve}`,
      );
    }
    const result = info.join("\n");
    this.log.debug(`${fnTag} ${result}`);
    return keyData;
  }

  /**
   * @description asynchronous request to get a new key and open new ws connection
   * @param args @type IClientNewKey
   */
  async getKey(args: IClientNewKey, sessionId: string): Promise<void> {
    try {
      this.keyData = this.initKey(args);
      await this.open(sessionId);
    } catch (error) {
      throw new Error(`Error setting client's key : ${error}`);
    }
  }

  /**
   * @description Closes existing and open new websocket connection for client
   */
  async open(sessionId: string): Promise<void> {
    const fnTag = `${this.className}#open`;
    await this.close();
    try {
      //const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.pubKey);
      const signature = sign(Buffer.from(sessionId, "hex"),this.keyData).toString(
        "hex",
      );
      const wsHostUrl = `${this.host}?sessionId=${sessionId}&signature=${signature}&crv=${this.keyData.curve}`;
      this.log.debug(`${fnTag} Open new WebSocket to host: ${wsHostUrl}`);
      this.ws = new WebSocket(wsHostUrl);
      await waitForSocketState(this.ws, this.ws.OPEN);
    } catch (error) {
      throw new Error(
        `Error creating web-socket connection to host ${this.host}: ${error}`,
      );
    }

    this.ws.onerror = function () {
      //throw new Error('require port for web socket');
    };
    this.ws.onopen = function () {
      console.log("WebSocket connection established");
    };
    const { host, keyName, ws, log, keyData } = this;
    this.ws.onclose = function incoming() {
      console.log(`Web socket connection to ${host} closed for key ${keyName}`);
    };
    this.ws.on("message", function incoming(message: Buffer) {
      const signature = sign(message,keyData);
      log.debug(`Send signature to web socket server ${ws.url}`);
      ws.send(signature);
    });
  }
  /**
   * @description : close the WebSocket
   */
  async close(): Promise<void> {
    if (this.ws) {
      this.ws.close();
      console.log('closing web socket')
      await waitForSocketState(this.ws, this.ws.CLOSED);
    }
  }
  /**
   * @description send out pubKey
   * @return pubKey pem file
   */
  getPubKeyHex() {
    const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.pubKey);
    return pubKeyHex;
  }
}

const jsrsasign = require("jsrsasign");
type IEcdsaCurves = {
  [key: string]: elliptic.ec;
};
const EC = elliptic.ec;
const ecdsaCurves = {};
for (const value in ECCurveType) {
  //const curve = elliptic.curves[value];
  ecdsaCurves[value] = new EC(value);
}

/**
 * @description generate
 * @param prehashed digest as Buffer
 * @returns signature as string
 */
function sign(digest: Buffer, keyData: KeyData): Buffer {
  //const fnTag = `${this.className}#sign`;
  const { prvKeyHex } = jsrsasign.KEYUTIL.getKey(keyData.key);
  const ecdsa = ecdsaCurves[keyData.curve];
  const signKey = ecdsa.keyFromPrivate(prvKeyHex, "hex");
  const sig = ecdsa.sign(digest, signKey);
  const signature = Buffer.from(sig.toDER());
  return signature;
}

/**
 * Forces a process to wait until the socket's `readyState` becomes the specified value.
 * @param socket The socket whose `readyState` is being watched
 * @param state The desired `readyState` for the socket
 */
export function waitForSocketState(
  socket: WebSocket,
  state: number,
): Promise<void> {
  return new Promise(function (resolve, reject) {
    try {
      setTimeout(function () {
        if (socket.readyState === state) {
          resolve();
        } else {
          waitForSocketState(socket, state).then(resolve);
        }
      });
    } catch (err) {
      reject(`Error wating for socket state ${state}: ${err} `);
    }
  });
}
