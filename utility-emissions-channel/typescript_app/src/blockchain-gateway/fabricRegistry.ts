// fabricRegistry.ts : interact with fabric-ca to enroll
// and register user
import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { FabricSigningCredentialType, PluginLedgerConnectorFabric } from '@hyperledger/cactus-plugin-ledger-connector-fabric';
import { IEnrollRegistrarRequest, IEnrollRegistrarResponse } from './I-fabricRegistry';
import { PluginKeychainVault } from '@hyperledger/cactus-plugin-keychain-vault';

export interface IFabricRegistryOptions {
    logLevel: LogLevelDesc;
    fabricClient: PluginLedgerConnectorFabric;
    orgCAs: {
        [key: string]: {
            mspId: string;
            ca: string;
        };
    };
    keychain: PluginKeychainVault;
    adminUsername: string;
    adminPassword: string;
}

interface IX509Cert {
    type: string; // X509
    mspId: string;
    certificate: string;
    privateKey: string;
}

export class FabricRegistry {
    static readonly CLASS_NAME = 'FabricRegistry';

    static readonly X509Type = 'X509';

    private readonly log: Logger;
    get className(): string {
        return FabricRegistry.CLASS_NAME;
    }

    constructor(private readonly opts: IFabricRegistryOptions) {
        this.log = LoggerProvider.getOrCreate({ level: opts.logLevel, label: this.className });
        const fnTag = `#constructor`;
        this.log.debug(`${fnTag} orgCAs : %o`, opts.orgCAs);
    }

    async enrollRegistrar(req: IEnrollRegistrarRequest): Promise<IEnrollRegistrarResponse> {
        const fnTag = '#enrollRegistrar';
        try {
            if (await this.opts.keychain.has(`${req.orgName}_${this.opts.adminUsername}`)) {
                throw new Error(`${this.opts.adminUsername} of organizations ${req.orgName} is already enrolled`);
            }
            const refCA = this.opts.orgCAs[req.orgName];
            this.log.debug(`${fnTag} enroll ${req.orgName}'s registrar with ${refCA.ca}`);
            const key = `${req.orgName}_${this.opts.adminUsername}`;
            await this.opts.fabricClient.enroll(
                {
                    keychainId: this.opts.keychain.getKeychainId(),
                    keychainRef: key,
                    type: FabricSigningCredentialType.X509,
                },
                {
                    enrollmentID: this.opts.adminUsername,
                    enrollmentSecret: this.opts.adminPassword,
                    caId: refCA.ca,
                    mspId: refCA.mspId,
                },
            );
            this.log.debug(`${fnTag} ${req.orgName}'s registrar successfully enrolled`)
            return {
                orgName: req.orgName,
                msp: refCA.mspId,
                caName: refCA.ca,
                info: 'ORG ADMIN REGISTERED',
            };
        } catch (error) {
            throw error;
        }
    }

    async enrollUser(userId: string, orgName: string, affiliation: string) {
        const fnTag = '#enrollUser';
        try {
            if (await this.opts.keychain.has(`${orgName}_${userId}`)) {
                throw new Error(`${userId} of organizations ${orgName} is already enrolled`);
            }
            const refCa = this.opts.orgCAs[orgName];
            if (!refCa) {
                throw new Error(`organizations ${orgName} doesn't exists`);
            }
            // check if admin is enrolled or not
            const adminKey = `${orgName}_${this.opts.adminUsername}`;
            const rawAdminCerts: string = await this.opts.keychain.get(adminKey);
            if (!rawAdminCerts) {
                throw new Error(`${orgName}'s admin is not enrolled, please enroll admin first`);
            }
            // register user
            const secret = await this.opts.fabricClient.register(
                {
                    keychainId: this.opts.keychain.getKeychainId(),
                    keychainRef: adminKey,
                    type: FabricSigningCredentialType.X509,
                },
                {
                    enrollmentID: userId,
                    affiliation: affiliation,
                    role: 'client',
                },
                refCa.ca,
            );

            this.log.debug(`${fnTag} enrolling ${userId}`);
            const key = `${orgName}_${userId}`;

            await this.opts.fabricClient.enroll(
                {
                    keychainId: this.opts.keychain.getKeychainId(),
                    keychainRef: key,
                    type: FabricSigningCredentialType.X509,
                },
                {
                    enrollmentID: userId,
                    enrollmentSecret: secret,
                    caId: refCa.ca,
                    mspId: refCa.mspId,
                },
            );
            this.log.debug(`${fnTag} ${userId} successfully enrolled`);
        } catch (error) {
            throw error;
        }
    }
}