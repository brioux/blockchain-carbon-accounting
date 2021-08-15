// Keycahin util to configure different keystore locations (e.g. vault, memory, client, ...)
import {PluginKeychainMemory} from '@hyperledger/cactus-plugin-keychain-memory';
import {PluginKeychainVault} from '@hyperledger/cactus-plugin-keychain-vault';
// TO-DO client keychain plugin for catctus does not exist yet... 
//import {PluginKeychainWebSocket} from '@hyperledger/cactus-plugin-keychain-web-socket';
import {ILedgerIntegrationConfig} from '../../config/ledger-config';
import {v4 as uuid4} from 'uuid';

interface orgKeychains{
    [key:string]:{
        admin:any;
        user?:{[key:string]:any};
    };
};
import { PluginRegistry} from '@hyperledger/cactus-core';

export class LedgerKeychains {
    readonly Memory:PluginKeychainMemory;
    readonly Vault:PluginKeychainVault;
    //private readonly WebSocket:PluginKeychainWebSocket;
    //private readonly filesystem:Wallet;
    org:orgKeychains;
    plugins:any[];


    constructor(private readonly ledgerConfig:ILedgerIntegrationConfig){

        // memory keychain from catcus plugin 
        this.Memory = new PluginKeychainMemory({
            instanceId: uuid4(),
            keychainId: ledgerConfig.keychainID,
            logLevel: ledgerConfig.logLevel
        });

        // vault keychain for storing private key and certificates of fabric client
        this.Vault = new PluginKeychainVault({
            keychainId : 'certKeychain',
            apiVersion: ledgerConfig.vaultKeychain.apiVersion,
            endpoint: ledgerConfig.vaultKeychain.endpoint,
            token: ledgerConfig.vaultKeychain.token,
            kvSecretsMountPath: `${ledgerConfig.vaultKeychain.kvMountPath}/data/`,
            instanceId: uuid4(),
            logLevel: ledgerConfig.logLevel
        });

        //this.filesystem = new Wallets().newFileSystemWallet({
        //
        //});

        //keychain plugin for storing keys in webSocket extension
        //this.WebSocket = new PluginKeychainWebSocket({});

        this.plugins = [this.Memory,this.Vault];
    }
}