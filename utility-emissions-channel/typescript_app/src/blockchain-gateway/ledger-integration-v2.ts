import { Express } from 'express';
import { VaultIdentityBackend } from '../identity/backend';
import { FabricRegistryRouterV2 } from '../routers/fabricRegistry-v2';
import { IdentityRouter } from '../routers/identity';
import { Request, Response } from 'express';
import { FabricRegistryV2 } from './fabricRegistry-v2';
import { LedgerConfig } from '../config/ledger-config-v2';
import { Checks } from '@hyperledger/cactus-common';
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
    }
}
