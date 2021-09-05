import { KEYUTIL } from 'jsrsasign';
import fs from 'fs'; 
const jsrsasign = require('jsrsasign');

export enum ECCurveType {
  p256 = "p256",
  p384 = "p384",
}
export enum ECCurveLong{
  p256 = 'secp256r1',
  p384 = 'secp384r1'
}
export interface IClientNewKey {
  keyName: string;
  curve?: ECCurveType;
}

export interface KeyData {
  curve: ECCurveType;
  key:string;
  pubKey:string;
}

const walletPath = `/Users/bertrandrioux/wallet`;
if(!fs.existsSync(walletPath)){
  console.log('Make directory to store keys at ${walletPath}');
  fs.mkdirSync(walletPath)
};

export function getKeyPath(keyName){
  return `${walletPath}/${keyName}.key`;
}
/**
 * @description will generate a new EC key pair, or throw an error if a key with the requested name already existis.
 * @param args; @type IClientNewKey
 * @return pubKeyHex;
 */
export function keyGen(args:IClientNewKey){
  try{
    let info = [];
    const keyPath = getKeyPath(args.keyName)
    if(fs.existsSync(keyPath)){ 
      return `${args.keyName} key already exists.`;
    }
    if(!args.curve){
      info.push('No curve specified. Set to p256 as default');
      args.curve = 'p256' as ECCurveType;
    }
    const ecdsaAlg = ECCurveLong[args.curve]; 
    info.push(`Create ${args.keyName} key with elliptical curve ${ecdsaAlg}`)
    const keyPair = KEYUTIL.generateKeypair('EC',ecdsaAlg)
    const key = KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS8PRV")
    const pubKey = KEYUTIL.getPEM(keyPair.pubKeyObj)
    const keyData = {key,pubKey,curve: args.curve};
    info.push(`Store private key data in ${keyPath}`)
    fs.writeFileSync(keyPath,JSON.stringify(keyData));
    const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(pubKey);
    info.push(`pubKeyHex: ${pubKeyHex}`)
    return info.join('\n');
  }catch(error){
    throw new Error(`Error generating key ${error}`);
  }
};

if(!fs.existsSync(walletPath)){
  console.log('Make directory to store keys at ${walletPath}');
  fs.mkdirSync(walletPath)
};

export function getPubKeyHex(keyName){
  const keyPath = getKeyPath(keyName)
  if(fs.existsSync(keyPath)){ 
    const keyData = JSON.parse(fs.readFileSync(keyPath,'utf8'));
    const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(keyData.pubKey);
    return `pubKeyHex: ${pubKeyHex}`
  }else{
    return `No key file found`
  }
}
export function listKeys(){
  let keys = [];
  fs.readdirSync(walletPath).forEach(file => {
    const tmp = file.split('.')
    if(tmp[1]=='key')
    keys.push(tmp[0])
  });
}

