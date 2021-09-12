import { IPluginKeychain } from '@hyperledger/cactus-core-api';
import {
    FabricSigningCredentialType,
    IVaultConfig,
    PluginLedgerConnectorFabric,
    IPluginLedgerConnectorFabricOptions,
} from '@hyperledger/cactus-plugin-ledger-connector-fabric';
import { PluginKeychainMemory } from '@hyperledger/cactus-plugin-keychain-memory';
import { Checks, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { v4 as uuid4 } from 'uuid';
import { PluginKeychainVault } from '@hyperledger/cactus-plugin-keychain-vault';
import { PluginRegistry } from '@hyperledger/cactus-core';
import { readFileSync } from 'fs';
import AWSS3 from '../blockchain-gateway/utils/aws';
export class LedgerConfig {
    fabricConnector: PluginLedgerConnectorFabric;
    inMemoryKeychain: IPluginKeychain;
    certStoreKeychain: IPluginKeychain;
    pluginRegistry: PluginRegistry;
    awss3: AWSS3;
    constructor(logLevel: LogLevelDesc) {
        const fnTag = 'LedgerConfig#constructor';
        const log = LoggerProvider.getOrCreate({ label: 'LedgerConfig', level: logLevel });
        this.awss3 = new AWSS3();
        this.inMemoryKeychain = new PluginKeychainMemory({
            instanceId: uuid4(),
            keychainId: 'inMemoryKeychain',
            logLevel: logLevel,
        });

        {
            const endpoint = process.env.VAULT_ENDPOINT;
            const certstorepath = process.env.VAULT_CERTSTORE_PATH;
            const token = process.env.VAULT_CERTSTORE_TOKEN;
            {
                Checks.nonBlankString(endpoint, `${fnTag} VAULT_ENDPOINT`);
                Checks.nonBlankString(certstorepath, `${fnTag} VAULT_CERTSTORE_PATH`);
                Checks.nonBlankString(token, `${fnTag} VAULT_CERTSTORE_TOKEN`);
            }
            this.certStoreKeychain = new PluginKeychainVault({
                instanceId: uuid4(),
                keychainId: 'certStoreKeychain',
                logLevel: logLevel,
                endpoint: endpoint,
                apiVersion: 'v1',
                kvSecretsMountPath: certstorepath + '/data/',
                token: token,
            });
        }

        {
            this.pluginRegistry = new PluginRegistry({
                plugins: [this.certStoreKeychain, this.inMemoryKeychain],
            });
        }
        {
            const identitySupport: FabricSigningCredentialType[] = [];
            let vaultConfig: IVaultConfig;
            {
                const iSupportString = process.env.LEDGER_FABRIC_IDENTITY_SUPPORT;
                Checks.nonBlankString(iSupportString, `${fnTag} FABRIC_IDENTITY_SUPPORT`);
                const iSupport = iSupportString.split(',');
                {
                    if (iSupport.includes('default')) {
                        identitySupport.push(FabricSigningCredentialType.X509);
                    }

                    if (iSupport.includes('vault')) {
                        const endpoint = process.env.VAULT_IDENTITY_ENDPOINT;
                        const transit = process.env.VAULT_IDENTITY_ENGINE_TRANSIT_PATH;
                        Checks.nonBlankString(endpoint, `${fnTag} VAULT_IDENTITY_ENDPOINT`);
                        Checks.nonBlankString(
                            transit,
                            `${fnTag} VAULT_IDENTITY_ENGINE_TRANSIT_PATH`,
                        );
                        vaultConfig = {
                            endpoint: endpoint,
                            transitEngineMountPath: '/' + transit,
                        };
                        identitySupport.push(FabricSigningCredentialType.VaultX509);
                    }
                    log.info(`${fnTag} FABRIC IDENTITY SUPPORT = ${identitySupport}`);
                }
            }
            const opts: IPluginLedgerConnectorFabricOptions = {
                logLevel: logLevel,
                connectionProfile: undefined,
                pluginRegistry: this.pluginRegistry,
                cliContainerEnv: {},
                instanceId: uuid4(),
                peerBinary: 'not-required',
                sshConfig: {},
                discoveryOptions: {
                    enabled: true,
                    asLocalhost: process.env.LEDGER_FABRIC_AS_LOCALHOST === 'true',
                },
                supportedIdentity: identitySupport,
                vaultConfig: vaultConfig,
            };
            {
                const ccpPath = process.env.LEDGER_FABRIC_CCP;
                Checks.nonBlankString(ccpPath, `${fnTag} LEDGER_FABRIC_CCP`);
                opts.connectionProfile = JSON.parse(readFileSync(ccpPath).toString('utf8'));
            }
            this.fabricConnector = new PluginLedgerConnectorFabric(opts);
        }
    }
}
