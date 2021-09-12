import { VaultIdentityBackend } from '../identity/backend';
import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { Router, Request, Response } from 'express';
import { header, query, validationResult } from 'express-validator';
import { randomBytes } from 'crypto';

export interface IIdentityRouterOptions {
    logLevel: LogLevelDesc;
    backend: VaultIdentityBackend;
}

export class IdentityRouter {
    private readonly log: Logger;
    readonly className = 'IdentityRouter';
    readonly router: Router;
    constructor(private readonly opts: IIdentityRouterOptions) {
        this.log = LoggerProvider.getOrCreate({ label: this.className, level: opts.logLevel });
        this.router = Router();
        this.__registerHandlers();
    }
    private __registerHandlers() {
        this.router.post(
            '/identity',
            [
                header('Authorization').isString().notEmpty().contains('Bearer '),
                query('username').isString().notEmpty(),
                query('type').custom((type) => {
                    if (!['MANAGER', 'CLIENT'].includes(type)) {
                        throw new Error(`require CLIENT | MANAGER, but provided : ${type}`);
                    }
                    return true;
                }),
            ],
            this.newIdentity.bind(this),
        );
        this.router.patch(
            '/identity',
            [
                header('Authorization').isString().notEmpty().contains('Bearer '),
                header('new_password').isString().notEmpty(),
            ],
            this.updateIdentityPassword.bind(this),
        );

        this.router.post(
            '/token',
            [header('username').isString().notEmpty(), header('password').isString().notEmpty()],
            this.genToken.bind(this),
        );
        this.router.patch(
            '/token',
            [header('Authorization').isString().notEmpty().contains('Bearer ')],
            this.renewToken.bind(this),
        );
        this.router.get(
            '/token',
            [header('Authorization').isString().notEmpty().contains('Bearer ')],
            this.getTokenDetails.bind(this),
        );
        this.router.delete(
            '/token',
            [header('Authorization').isString().notEmpty().contains('Bearer ')],
            this.revokeToken.bind(this),
        );

        this.router.get(
            '/secrets',
            [header('Authorization').isString().notEmpty().contains('Bearer ')],
            this.getSecrets.bind(this),
        );

        this.router.post(
            '/secrets/eth',
            [
                header('Authorization').isString().notEmpty().contains('Bearer '),
                header('address').isHexadecimal(),
                header('private').isHexadecimal(),
            ],
            this.setEthSecret.bind(this),
        );
        this.router.post(
            '/secrets/fabric',
            [
                header('Authorization').isString().notEmpty().contains('Bearer '),
                header('enrollmentSecret').isString(),
            ],
            this.setFabricSecret.bind(this),
        );
        this.router.post(
            '/key',
            [
                header('Authorization').isString().notEmpty().contains('Bearer '),
                query('kty').custom((input) => {
                    if (!['ecdsa-p256', 'ecdsa-p384'].includes(input)) {
                        throw new Error(
                            `require 'ecdsa-p256' | 'ecdsa-p384', but provided : ${input}`,
                        );
                    }
                    return true;
                }),
            ],
            this.newTransitKey.bind(this),
        );
    }

    private async newIdentity(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        const username = req.query.username as string;
        const password: string = randomBytes(16).toString('hex');
        this.log.debug(
            `${fnTag} creating identity , username = ${username}, type = ${req.query.type}`,
        );
        if (req.query.type === 'CLIENT') {
            try {
                await this.opts.backend.createClientIdentity(token, username, password);
            } catch (error) {
                this.log.error(`${fnTag} failed to create a client identity ${error}`);
                return res.status(209).json({
                    msg: (error as Error).message,
                });
            }
        } else if (req.query.type === 'MANAGER') {
            try {
                await this.opts.backend.createManagerIdentity(token, username, password);
            } catch (error) {
                this.log.error(`${fnTag} failed to create a manager identity ${error}`);
                return res.status(209).json({
                    msg: (error as Error).message,
                });
            }
        }
        this.log.debug(`${fnTag} identity created with username = ${username}`);
        return res.status(201).json({
            username: username,
            password: password,
        });
    }
    private async updateIdentityPassword(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        this.log.debug(`${fnTag} fetching token details`);
        let username: string;
        try {
            const cred = await this.opts.backend.tokenDetails(token);
            username = cred.username;
        } catch (error) {
            this.log.debug(`${fnTag} failed to fetch token details: ${error.message}`);
            return res.status(403).json({
                msg: (error as Error).message,
            });
        }
        this.log.debug(`${fnTag} updating ${username}'s password`);
        const newPassword = req.header('new_password');
        try {
            await this.opts.backend.updateIdentityPassword(token, username, newPassword);
        } catch (error) {
            this.log.debug(`${fnTag} failed to generate token : ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
        this.log.debug(`${fnTag} identity password updated for ${username}`);
        return res.status(204).send();
    }

    private async genToken(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const username = req.header('username');
        const password = req.header('password');
        this.log.debug(`${fnTag} generating new token for ${username}`);
        let token: string;
        try {
            token = await this.opts.backend.genToken(username, password);
        } catch (error) {
            this.log.debug(`${fnTag} failed to generate token : ${error.message}`);
            return res.status(403).json({
                msg: (error as Error).message,
            });
        }
        this.log.debug(`${fnTag} new token generated for ${username}`);
        return res.status(200).json({
            token: token,
        });
    }
    private async renewToken(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        try {
            await this.opts.backend.renewToken(token);
        } catch (error) {
            this.log.debug(`${fnTag} failed to renew token : ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
        this.log.debug(`${fnTag} token renewed`);
        return res.status(200).send();
    }
    private async getTokenDetails(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        try {
            const details = await this.opts.backend.tokenDetails(token);
            return res.status(200).json(details);
        } catch (error) {
            this.log.debug(`${fnTag} failed to renew token : ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
    }
    private async revokeToken(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        try {
            await this.opts.backend.revokeToken(token);
            return res.status(204).send();
        } catch (error) {
            this.log.debug(`${fnTag} failed to get token details: ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
    }

    private async getSecrets(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        this.log.debug(`${fnTag} fetching token details`);
        let username: string;
        try {
            const cred = await this.opts.backend.tokenDetails(token);
            username = cred.username;
        } catch (error) {
            this.log.debug(`${fnTag} failed to fetch token details: ${error.message}`);
            return res.status(403).json({
                msg: (error as Error).message,
            });
        }
        this.log.debug(`${fnTag} fetching ${username}'s secrets`);
        try {
            let secrets: { [key: string]: string } = {};
            try {
                secrets = await this.opts.backend.getKVSecret(token, username);
            } catch (e) {}
            const out: { key: string; value: string }[] = [];
            for (const secret in secrets) {
                out.push({ key: secret, value: secrets[secret] });
            }
            return res.status(200).json(out);
        } catch (error) {
            this.log.debug(`${fnTag} failed to get client's secrets: ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
    }

    private async setFabricSecret(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        this.log.debug(`${fnTag} fetching token details`);
        let username: string;
        try {
            const cred = await this.opts.backend.tokenDetails(token);
            username = cred.username;
        } catch (error) {
            this.log.debug(`${fnTag} failed to fetch token details: ${error.message}`);
            return res.status(403).json({
                msg: (error as Error).message,
            });
        }

        this.log.debug(`${fnTag} setting fabric secret for ${username}`);
        try {
            let secrets: { [key: string]: string } = {};
            try {
                secrets = await this.opts.backend.getKVSecret(token, username);
            } catch (e) {}
            secrets['ENROLLMENT_SECRET'] = req.header('enrollmentSecret');
            await this.opts.backend.setKVSecret(token, username, secrets);

            return res.sendStatus(200);
        } catch (error) {
            this.log.debug(`${fnTag} failed to set fabric secret: ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
    }
    private async setEthSecret(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        this.log.debug(`${fnTag} fetching token details`);
        let username: string;
        try {
            const cred = await this.opts.backend.tokenDetails(token);
            username = cred.username;
        } catch (error) {
            this.log.debug(`${fnTag} failed to fetch token details: ${error.message}`);
            return res.status(403).json({
                msg: (error as Error).message,
            });
        }
        this.log.debug(`${fnTag} setting eth secret for ${username}`);
        try {
            const secrets = await this.opts.backend.getKVSecret(token, username);
            secrets['ETHEREUM_KEY'] = JSON.stringify({
                address: req.header('address'),
                private: req.header('private'),
            });
            await this.opts.backend.setKVSecret(token, username, secrets);
            return res.sendStatus(200);
        } catch (error) {
            this.log.debug(`${fnTag} failed to set eth secret: ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
    }
    private async newTransitKey(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(412).json({
                msg: errors.array(),
            });
        }
        const token = req.header('Authorization').split('Bearer ')[1];
        this.log.debug(`${fnTag} fetching token details`);
        let username: string;
        try {
            const cred = await this.opts.backend.tokenDetails(token);
            username = cred.username;
        } catch (error) {
            this.log.debug(`${fnTag} failed to fetch token details: ${error.message}`);
            return res.status(403).json({
                msg: (error as Error).message,
            });
        }
        const kty = req.query.kty;
        this.log.debug(`${fnTag} creating transit key for ${username} , type = ${kty}`);
        try {
            await this.opts.backend.createTransitKey(
                token,
                username,
                kty as 'ecdsa-p256' | 'ecdsa-p384',
            );
            this.log.debug(`${fnTag} transit key created of type = ${kty}`);
            return res.status(201).send();
        } catch (error) {
            this.log.debug(`${fnTag} failed to create transit key: ${error.message}`);
            return res.status(409).json({
                msg: (error as Error).message,
            });
        }
    }
}
