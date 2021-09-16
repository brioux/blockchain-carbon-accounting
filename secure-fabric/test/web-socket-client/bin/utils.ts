import yargs from "yargs";
import { WebSocketClient } from '../src/client';
import { keyGen, getPubKeyHex, listKeys, IClientNewKey } from '../src/key';

let usage = "\nUsage: ws-client\n";
usage+="\tnew-key <keyname> [<curve>]\t" + "Generate a new key with optional curve: 'p256' | 'p384\n"
usage+="\tget-pkh <keyname>          \t" + "Get publick key hex of keyname\n"
usage+="\tconnect <host> <sessionId> [<keyname>] \t" + "connect sessionId with host of web socket server. keyname optional (use default)\n"

function showHelp() {                                                            
    console.log(usage);   
    console.log('\nOptions:\r')
    console.log('   \t--version\t' + 'Show version number.' + '\t\t' + '[boolean]\r')
    console.log('-k,\t--keys   \t' + 'List all keys.      ' + '\t\t' + '[boolean]\r')
    console.log('   \t--help   \t' + 'Show help.          ' + '\t\t' + '[boolean]\n')
}

async function getClient(host,sessionId,args:IClientNewKey) {                                                          
    const wsClient = new WebSocketClient({host,keyName:args.keyName})
    await wsClient.getKey(args,sessionId);
    console.log(`Built client to connect to host: ${host}`)
}
//async function closeClients(client,args:IClientNewKey) { 

async function generateKey(args:IClientNewKey) {                                                            
    const res = keyGen(args);
    console.log(res);
}

export default { usage, showHelp, getClient, generateKey, getPubKeyHex, listKeys };