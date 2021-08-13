# Project Proposal

## Background

One question that every person designing a HL fabric based solution ask is : **What the hack should I do with private key and certificates of clients?** . Although `fabric-sdk` provide two different kind of approaches.

1. storing client's private key and certificate together on some database (which implements wallet interface). For this approach a rough flow goes something like this
     - client send request to `org's application` server to `invoke` or `query` chaincode using a give `KEY`.
     - `org's application` upon receiving the request , it fetches `private key` and `certificate` corresponding to `KEY`.
     - uses the fetched private key to sign fabric `message` in order to query or invoke chaincode. <br>NOTE : developer of the application has to implement authentication for client's `KEY`

2. store private key in HSM , but in this approach `application` and `HSM` have to be present on same physical machine (i.e `HSM` should directly be connected with `machine` running the application). This approach is mostly used for developing client's desktop application, which will be responsible for communicating with fabric peers.

- Major Advantage in First approach : clients won't be responsible for communicating with fabric network
- Major Disadvantage in First approach : all private key are stored in single database which leads to `money pot` for hackers to exploit .
- Major Advantage in Second approach : client's private key are never exposed to `org's` application.
- Major Disadvantage in Second approach : clients are responsible for communicating with fabric network

**Now comes the `fabric-secure-connector`** which only brings the advantages from both the approaches. Secure Fabric connector provides a solution to the fabric organization for managing their client's private key such that the client's private key is never brought to `Node Server` for singing. Currently `fabric-secure-connector` provide a option of keeping client's private key into `Vault Transit Engine` or in browser `Extension` (TODO).

## Top Level exported `class` and `interface`

```ts
export enum IdentityProvidersType {
     // identity by default provided by fabric-sdk-node wherein private key and certificate
     // stored together (First approach)
     Default = 'Default-X.509'


     // vault identity provider wherein private key are store with vault transit engine
     // and certificate are store in certData store
     Vault = 'Vault-X.509',

     // [ TRANSPORT ] WebSocket identity provider wherein private key are store with client inside the extension
     // signing of digest are done by sending of data as websocket message through webSocket connection between
     // server and client extension
     // certificate are store in certData store
     WebSocket = 'WS-X.509',

     // [ TRANSPORT ] gRPC identity provider wherein private key are store with client inside the extension
     // signing of digest are done by sending of data as gRPC streaming gRPC bi-directional connection 
     // between server and client extension
     // certificate are store in certData store
     gRPC = 'gRPC-X.509',
}
```

```ts
// every identity  type and certificate data will extends this interface
interface IIdentity{
     // key used for storing identity data with cert datastore
     key:string
     type:IdentityProvidersType
} 
```

```ts
// IVaultIdentity represents a vault client.
export interface IVaultIdentity extends IIdentity{
     keyName:string
     token:string
}

// IWebsocketIdentity represents a websocket client.
// message signing will be done by back and forth message between 
// server and client over weConn
export interface IWebsocketIdentity extends IIdentity{
     wsConn:connection
}

// IGRPCIdentity represents a bi-directional gRPC client.
// message signing will be done by back and forth message between 
// server and client over weConn
export interface IGRPCIdentity extends IIdentity{
     biConn:connection
}

// IIdentityData : data that will be stored with cert datastore
// with key as client's commonName (from X509 certificate) and value as following field
interface IIdentityData extends IIdentity{
     credentials: {
          certificate: string;
          // if identity type is IdentityProvidersType.Default
          privateKey?:string;
     };
     mspId: string;
}
```

```ts

export interface ISecureFabricConnector{
     // array of identity types that application is going to support
     // eg [IdentityProvidersType.Vault , IdentityProvidersType.Default IdentityProvidersType.WebSocket]
     // this will accept client request with vault , default or websocket for signing fabric messages
     supportedIdentity:IdentityProvidersType[]


     // vault server config if Vault identity is support 
     vaultOptions?:{endpoint:string,transitEngineMountPath:string}

     // for registering client : NOTE /register endpoint should not be exposed to client
     // rather this endpoint is for org's admin
     registrar : {
          certificate:string
          mspId:string
          // if privateKey is provided , this private will be used for signing
          privateKey?:string

          // if provided , application will use private key of registerer stored with vault
          // to register and revoke client
          vaultKey?:{token:string,keyName:string}
     }
     // usual field required in fabric-sdk-node's GatewayOptions
    connectionProfile:object
    tlsInfo?: {
        certificate: string;
        key: string;
    };
    discovery?: DiscoveryOptions;
    eventHandlerOptions?: DefaultEventHandlerOptions;
    queryHandlerOptions?: DefaultQueryHandlerOptions;
    'connection-options'?: any;
}
```
```ts
export class ISecureFabricConnector{
     constructor(ISecureFabricConnector)

     /**
      * @method transact invoke/query fabric chaincode
      * @param caller client identity
      * @param channel on which chaincode is committed
      * @param ccName : fabric chaincode name
      * @param method supported by chaincode
      * @param args , method specific arguments
      */
     transact(type:'query'|'invoke',caller:IIdentity,channel:string,ccName:string,method:string,...args:string[]):Promise<Buffer>

     /**
      * @method enroll a already registered client
      * @param caller client identity
      * @param request for enrollment
      */
     enroll(caller:IIdentity,request:{enrollmentID:string,enrollmentSecret:string}):Promise<void>

     /**
      * @method rotateKey will rotate client key and store newly enrolled certificate in cert datastore
      * 
      */
     rotateKey(caller:IIdentity):Promise<void>
}
```