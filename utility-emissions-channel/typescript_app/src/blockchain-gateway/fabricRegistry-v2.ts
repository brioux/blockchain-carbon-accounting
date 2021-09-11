import { LogLevelDesc, Logger, LoggerProvider } from '@hyperledger/cactus-common';
import {
    FabricSigningCredential,
    FabricSigningCredentialType,
    PluginLedgerConnectorFabric,
} from '@hyperledger/cactus-plugin-ledger-connector-fabric';
import { IPluginKeychain } from '@hyperledger/cactus-core-api';
import { IEnrollRequest, IRegistrarRequest, IRegistrarResponse } from './I-fabricRegistry-v2';
import { VaultIdentityBackend } from '../identity/backend';
import { randomBytes } from 'crypto';

export interface IFabricRegistryV2Options {
    logLevel: LogLevelDesc;
    fabricConnector: PluginLedgerConnectorFabric;
    certstoreKeychain: IPluginKeychain;
    vaultBackend: VaultIdentityBackend;
    caId: string;
    orgMSP: string;
}

export class FabricRegistryV2 {
    readonly className = 'FabricRegistryV2';
    private readonly log: Logger;
    readonly ENROLLMENT_SECRET_K = 'ENROLLMENT_SECRET';
    constructor(private readonly opts: IFabricRegistryV2Options) {
        this.log = LoggerProvider.getOrCreate({ label: this.className, level: opts.logLevel });
    }

    async enroll(req: IEnrollRequest): Promise<void> {
        const fnTag = `${this.className}#enroll`;
        this.log.debug(`${fnTag} enrolling ${req.username} of type = ${req.callerType}`);
        const signer: FabricSigningCredential = {
            keychainId: this.opts.certstoreKeychain.getKeychainId(),
            keychainRef: req.username,
            type: req.callerType,
        };

        if (signer.type === FabricSigningCredentialType.VaultX509) {
            signer.vaultTransitKey = {
                keyName: req.username,
                token: req.token,
            };
        }
        let secret = req.secret;
        if (!secret) {
            this.log.debug(`${fnTag} secret not provided fetching from vault`);
            try {
                const secrets = await this.opts.vaultBackend.getKVSecret(req.token, req.username);
                if (!secrets[this.ENROLLMENT_SECRET_K]) {
                    throw new Error(`${fnTag} enrollment secret not stored in vault`);
                }
                secret = secrets[this.ENROLLMENT_SECRET_K];
            } catch (error) {
                this.log.error(`${fnTag} failed to fetch secret from vault : %o`, error);
                throw error;
            }
        }
        try {
            await this.opts.fabricConnector.enroll(signer, {
                enrollmentID: req.username,
                enrollmentSecret: secret,
                mspId: this.opts.orgMSP,
                caId: this.opts.caId,
            });
            this.log.debug(`${fnTag} enrolled ${req.username} of type = ${req.callerType}`);
        } catch (error) {
            this.log.error(
                `${fnTag} failed to enroll client of type ${req.callerType} : %o`,
                error,
            );
            throw error;
        }
    }

    async register(req: IRegistrarRequest): Promise<IRegistrarResponse> {
        const fnTag = `${this.className}#register`;
        this.log.debug(`${fnTag} enrolling ${req.username} of type = ${req.callerType}`);
        const signer: FabricSigningCredential = {
            keychainId: this.opts.certstoreKeychain.getKeychainId(),
            keychainRef: req.username,
            type: req.callerType,
        };

        if (signer.type === FabricSigningCredentialType.VaultX509) {
            signer.vaultTransitKey = {
                keyName: req.username,
                token: req.token,
            };
        }
        this.log.debug(`${fnTag} registering ${req.enrollmentID}`);
        try {
            const password = randomBytes(16).toString('hex');
            await this.opts.fabricConnector.register(
                signer,
                {
                    enrollmentID: req.enrollmentID,
                    enrollmentSecret: password,
                    affiliation: req.affiliation,
                    maxEnrollments: req.maxEnrollments || -1,
                    attrs: req.attrs,
                    role: req.role || 'client',
                },
                this.opts.caId,
            );
            return { enrollmentSecret: password, enrollmentID: req.enrollmentID };
        } catch (error) {
            this.log.error(`${fnTag} failed to register client : %o`, error);
            throw error;
        }
    }
}
