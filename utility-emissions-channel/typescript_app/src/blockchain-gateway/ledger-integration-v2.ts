import { Express } from 'express';
import { VaultIdentityBackend } from '../identity/backend';
import { FabricRegistryRouterV2 } from '../routers/fabricRegistry-v2';
import { IdentityRouter } from '../routers/identity';
import { Request, Response } from 'express';
import { FabricRegistryV2 } from './fabricRegistry-v2';
import { LedgerConfig } from '../config/ledger-config-v2';
import { Checks } from '@hyperledger/cactus-common';
import { UtilityEmissionsChannelV2 } from './utilityEmissionsChannel-v2';
import { UtilityEmissionsChannelRouterV2 } from '../routers/utilityEmissionsChannel-v2';
import { NetEmissionsTokenNetworkContractV2 } from './netEmissionsTokenNetwork-v2';
import { contractName, abi } from '../contracts/NetEmissionsTokenNetwork.json';
import { CarbonAccountingRouterV2 } from '../routers/carbonAccounting-v2';
export class LedgerIntegrationV2 {
    readonly className = 'LedgerIntegrationV2';
    constructor(readonly app: Express) {
        const logLevel = 'DEBUG';
        const vaultBackend = new VaultIdentityBackend(logLevel);

        const ledgerConfig = new LedgerConfig(logLevel);

        // vault token based authentication
        const auth = async (req: Request, res: Response, next) => {
            const bearerHeader = req.header('Authorization');
            if (!bearerHeader) {
                return res.sendStatus(403);
            }
            const token = bearerHeader.split(' ')[1];
            try {
                const details = await vaultBackend.tokenDetails(token);
                (req as any).token = token;
                (req as any).username = details.username;
                next();
            } catch (error) {
                return res.sendStatus(403);
            }
        };

        {
            // start identity manager
            const identityRouter = new IdentityRouter({
                logLevel: logLevel,
                backend: vaultBackend,
            });
            app.use('/api/v2/im', identityRouter.router);
        }
        {
            const fnTag = `${this.className}#fabricRegistry`;
            const caID = process.env.LEDGER_FABRIC_ORG_CA;
            const orgMSP = process.env.LEDGER_FABRIC_ORG_MSP;
            {
                Checks.nonBlankString(caID, `${fnTag} LEDGER_FABRIC_ORG_CA`);
                Checks.nonBlankString(orgMSP, `${fnTag} LEDGER_FABRIC_ORG_MSP`);
            }
            // fabric registry v2
            const fabricRegistry = new FabricRegistryV2({
                logLevel: logLevel,
                vaultBackend: vaultBackend,
                fabricConnector: ledgerConfig.fabricConnector,
                certstoreKeychain: ledgerConfig.certStoreKeychain,
                caId: caID,
                orgMSP: orgMSP,
            });
            const fabricRegistryRouter = new FabricRegistryRouterV2({
                logLevel: logLevel,
                registry: fabricRegistry,
            });
            app.use(
                '/api/v2/utilityemissionchannel/registerEnroll',
                auth,
                fabricRegistryRouter.router,
            );
        }

        // utility emissions routers
        const utilityEmissionsChannel = new UtilityEmissionsChannelV2({
            logLevel: logLevel,
            fabricConnector: ledgerConfig.fabricConnector,
            certStoredKeycahinId: ledgerConfig.certStoreKeychain.getKeychainId(),
            dataStorage: ledgerConfig.awss3,
            orgName: process.env.LEDGER_FABRIC_ORG_MSP,
        });

        const utilityEmissionsChannelRouterV2 = new UtilityEmissionsChannelRouterV2({
            logLevel: logLevel,
            utilityEmissionsChannel: utilityEmissionsChannel,
        });
        app.use(
            '/api/v2/utilityemissionchannel/emissionscontract',
            auth,
            utilityEmissionsChannelRouterV2.router,
        );

        {
            // carbon accounting router
            const fnTag = `${this.className}#carbonAccounting`;
            const ccAddress = process.env.LEDGER_EMISSION_TOKEN_CONTRACT_ADDRESS;
            Checks.nonBlankString(ccAddress, `${fnTag} LEDGER_EMISSION_TOKEN_CONTRACT_ADDRESS`);
            const netEmissionsToken = new NetEmissionsTokenNetworkContractV2({
                logLevel: logLevel,
                ethConnector: ledgerConfig.ethConnector,
                contractName: contractName,
                contractAddress: ccAddress,
                contractStorekeychainID: ledgerConfig.inMemoryKeychain.getKeychainId(),
                vaultBackend: vaultBackend,
            });
            {
                // store contract in memory
                const network = process.env.LEDGER_ETH_NETWORK;
                Checks.nonBlankString(network, `${fnTag} LEDGER_ETH_NETWORK`);
                const networks: { [key: number]: any } = {};
                networks[this.__getEthNetworkID(network)] = {
                    address: ccAddress,
                };
                const json = {
                    abi: abi,
                    networks: networks,
                };
                ledgerConfig.inMemoryKeychain
                    .set(contractName, JSON.stringify(json))
                    .then(() => {
                        console.log(`${fnTag} contract stored`);
                    })
                    .catch((err) => {
                        console.error('failed to store contract : %o', err);
                        process.exit(1);
                    });
            }
            const carbonAccountingRouter = new CarbonAccountingRouterV2({
                logLevel: logLevel,
                netEmissionsTokenContract: netEmissionsToken,
                utilityEmissionChannel: utilityEmissionsChannel,
                orgName: process.env.LEDGER_FABRIC_ORG_MSP,
            });
            app.use(
                '/api/v2/utilityemissionchannel/emissionscontract',
                auth,
                carbonAccountingRouter.router,
            );
        }
    }
    private __getEthNetworkID(network: string): number {
        switch (network) {
            case 'hardhat':
                return 1337;
            case 'goerli':
                return 5;
            case 'ropsten':
                return 3;
            default:
                throw new Error(
                    'LEDGER_ETH_NETWORK : hardhat || goerli || ropsten ethereum network are supported',
                );
        }
    }
}
