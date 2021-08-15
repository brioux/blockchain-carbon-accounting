export enum IdentityProvidersType {
  // default identity provider, provided by fabric-sdk
  // wherein private and certificate are stored together
  Default = 'Default-X.509',

  // vault identity provider wherein private key are store with vault transit engine
  // and certificate are store in certData store
  Vault = 'Vault-X.509',

  // WebSocket identity provider wherein private key are store with client inside the extension
  // signing of digest are done by sending of data as websocket message through webSocket connection between
  // server and client extension
  // certificate are store in certData store
  WebSocket = 'WS-X.509',
}
