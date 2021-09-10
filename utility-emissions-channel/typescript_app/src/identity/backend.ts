import { LogLevelDesc, LoggerProvider, Logger, Checks } from '@hyperledger/cactus-common';
import Vault, { client } from 'node-vault';
export interface ITokenDetails {
    username: string;
    issue_time: string;
    expire_time: string;
}
export class VaultIdentityBackend {
    readonly className = 'VaultIdentityBackend';
    private readonly log: Logger;
    private cfg: {
        endpoint: string;
        secretPath: string;
        transitPath: string;
        userpassPath: string;
        clientPolicy: string;
        managerPolicy: string;
        userpassAccessor: string;
    };
    constructor(logLevel: LogLevelDesc) {
        this.log = LoggerProvider.getOrCreate({ label: 'VaultIdentityBackend', level: logLevel });
        this.__readEnvs();
    }

    async createTransitKey(
        token: string,
        username: string,
        type: 'ecdsa-p256' | 'ecdsa-p384',
    ): Promise<void> {
        const backend = this.__client(token);
        await backend.write(`${this.cfg.transitPath}/keys/${username}`, { type: type });
    }

    // secret engine
    async setKVSecret(
        token: string,
        username: string,
        secret: { [key: string]: any },
    ): Promise<void> {
        const backend = this.__client(token);
        await backend.write(`${this.cfg.secretPath}/data/${username}`, {
            data: secret,
        });
    }

    async getKVSecret(token: string, username: string): Promise<{ [key: string]: string }> {
        const backend = this.__client(token);
        const resp = await backend.read(`${this.cfg.secretPath}/data/${username}`);
        return resp.data.data;
    }

    async genToken(username: string, password: string): Promise<string> {
        const backend = this.__client();
        const resp = await backend.write(`auth/${this.cfg.userpassPath}/login/${username}`, {
            password: password,
        });
        return resp.auth.client_token;
    }

    async tokenDetails(token: string): Promise<ITokenDetails> {
        const fnTag = `${this.className}#tokenDetails`;
        const backend = this.__client(token);
        const resp = await backend.read(`auth/token/lookup-self`);
        if (resp?.data) {
            return {
                expire_time: resp.data.expire_time,
                issue_time: resp.data.issue_time,
                username: resp.data.meta.username,
            };
        }
        throw new Error(`${fnTag} invalid response from vault`);
    }
    async renewToken(token: string): Promise<void> {
        const backend = this.__client(token);
        await backend.write(`auth/token/renew-self`, {});
    }

    async revokeToken(token: string): Promise<void> {
        const backend = this.__client(token);
        await backend.write(`auth/token/revoke-self`, {});
    }

    async updateIdentityPassword(token: string, username: string, newPass: string): Promise<void> {
        const backend = this.__client(token);
        await backend.write(`auth/${this.cfg.userpassPath}/users/${username}/password`, {
            password: newPass,
        });
    }

    async createManagerIdentity(
        rootToken: string,
        username: string,
        password: string,
    ): Promise<void> {
        const fnTag = '#createManagerIdentity';
        await this.__createIdentity(fnTag, rootToken, username, password, this.cfg.managerPolicy);
        this.log.debug(`${fnTag} identity of manager successfully created with vault`);
    }
    async createClientIdentity(
        managerToken: string,
        username: string,
        password: string,
    ): Promise<void> {
        const fnTag = '#createClientIdentity';
        await this.__createIdentity(fnTag, managerToken, username, password, this.cfg.clientPolicy);
        this.log.debug(`${fnTag} identity of manager successfully created with vault`);
    }

    private async __createIdentity(
        fnTag: string,
        token: string,
        username: string,
        password: string,
        policy,
    ): Promise<void> {
        this.log.debug(`${fnTag} create userpass for identity with username = ${username}`);
        const backend = this.__client(token);
        try {
            await backend.write(`auth/${this.cfg.userpassPath}/users/${username}`, {
                password: password,
            });
        } catch (error) {
            throw new Error(
                `${fnTag} failed to create userpass for ${username} : ${error.message}`,
            );
        }
        this.log.debug(`${fnTag} create entity for ${username}`);
        let entityId: string;
        try {
            const resp = await backend.write('identity/entity', {
                name: username,
                policies: [policy],
            });
            if (resp?.data?.id) {
                entityId = resp.data.id;
            } else {
                throw new Error(`${fnTag} invalid response from vault path : identity/entity`);
            }
        } catch (error) {
            throw new Error(`${fnTag} failed to create entity for ${username} : ${error.message}`);
        }
        this.log.debug(`${fnTag} create entity-alias for ${username}`);
        try {
            await backend.write('identity/entity-alias', {
                name: username,
                canonical_id: entityId,
                mount_accessor: this.cfg.userpassAccessor,
            });
        } catch (error) {
            throw new Error(
                `${fnTag} failed to create entity-alias for ${username} : ${error.message}`,
            );
        }
    }
    // read config envs and create vault identity backend
    private __readEnvs() {
        const fnTag = `${this.className}#readEnvs`;
        this.cfg = {
            endpoint: process.env.VAULT_IDENTITY_ENDPOINT,
            secretPath: process.env.VAULT_IDENTITY_ENGINE_SECRET_PATH,
            transitPath: process.env.VAULT_IDENTITY_ENGINE_TRANSIT_PATH,
            userpassPath: process.env.VAULT_IDENTITY_AUTH_USERPASS_PATH,
            clientPolicy: process.env.VAULT_IDENTITY_POLICY_CLIENT,
            managerPolicy: process.env.VAULT_IDENTITY_POLICY_MANAGER,
            userpassAccessor: process.env.VAULT_IDENTITY_AUTH_USERPASS_ACCESSOR,
        };
        {
            Checks.nonBlankString(this.cfg.endpoint, `${fnTag} VAULT_IDENTITY_ENDPOINT`);
            Checks.nonBlankString(
                this.cfg.secretPath,
                `${fnTag} VAULT_IDENTITY_ENGINE_SECRET_PATH`,
            );
            Checks.nonBlankString(
                this.cfg.transitPath,
                `${fnTag} VAULT_IDENTITY_ENGINE_TRANSIT_PATH`,
            );
            Checks.nonBlankString(
                this.cfg.userpassPath,
                `${fnTag} VAULT_IDENTITY_AUTH_USERPASS_PATH`,
            );
            Checks.nonBlankString(
                this.cfg.userpassAccessor,
                `${fnTag} VAULT_IDENTITY_AUTH_USERPASS_ACCESSOR`,
            );
            Checks.nonBlankString(this.cfg.clientPolicy, `${fnTag} VAULT_IDENTITY_POLICY_CLIENT`);
            Checks.nonBlankString(this.cfg.managerPolicy, `${fnTag} VAULT_IDENTITY_POLICY_MANAGER`);
        }
    }

    private async __initialize() {
        const resp = await this.__client().read('sys/health');
        this.log.info(`Vault Server Health`);
        this.log.info(resp);
        this.log.info('='.repeat(20));
    }

    private __client(token?: string): client {
        return Vault({
            endpoint: this.cfg.endpoint,
            apiVersion: 'v1',
            token: token,
        });
    }
}
