import { Router, Request, Response } from 'express';
import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { FabricRegistryV2 } from '../blockchain-gateway/fabricRegistry-v2';
import { query, validationResult, body } from 'express-validator';

export interface IFabricRegistryV2Options {
    logLevel: LogLevelDesc;
    registry: FabricRegistryV2;
}

export class FabricRegistryRouterV2 {
    private readonly log: Logger;
    readonly className = 'FabricRegistryV2';
    readonly router: Router;
    constructor(private readonly opts: IFabricRegistryV2Options) {
        this.log = LoggerProvider.getOrCreate({ label: this.className, level: opts.logLevel });
        this.router = Router();
        this.__registerHandlers();
    }

    private __registerHandlers() {
        this.router.post(
            '/enroll',
            [query('callerType').custom((input) => this.__callerType(input))],
            this.enroll.bind(this),
        );
        this.router.post(
            '/register',
            [
                query('callerType').custom((input) => this.__callerType(input)),
                body('enrollmentID').isString().notEmpty(),
                body('role').isString().notEmpty(),
                body('affiliation').isString().notEmpty(),
                body('maxEnrollments').isNumeric().optional(),
                body('attrs.*.name').isString().notEmpty(),
                body('attrs.*.value').isString().notEmpty(),
                body('attrs.*.ecert').isBoolean().optional(),
            ],
            this.register.bind(this),
        );
    }
    private async enroll(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        try {
            await this.opts.registry.enroll({
                callerType: req.query.callerType as any,
                username: (req as any).username,
                vaultKey: {
                    keyName: (req as any).username, 
                    token: (req as any).token,
                },
                webSocketKey: {
                    sessionId: (req as any).sessionId,
                    signature: (req as any).signature,
                },
                secret: req.header('enrollmentSecret'),
            });
            return res.sendStatus(200);
        } catch (error) {
            return res.status(409).json({
                msg: error.message,
            });
        }
    }

    private async register(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        try {
            const resp = await this.opts.registry.register({
                callerType: req.query.callerType as any,
                username: (req as any).username,
                vaultKey:{
                    keyName: (req as any).username,
                    token: (req as any).token,
                },
                webSocketKey: {
                    sessionId: (req as any).sessionId,
                    signature: (req as any).signature,
                },
                enrollmentID: req.body.enrollmentID,
                role: req.body.role,
                affiliation: req.body.affiliation,
                maxEnrollments: req.body.maxEnrollments,
                attrs: req.body.attrs,
            });
            return res.status(201).json(resp);
        } catch (error) {
            return res.status(409).json({
                msg: error.message,
            });
        }
    }

    private __callerType(input): boolean {
        if (!['X.509', 'Vault-X.509', 'WS-X.509'].includes(input)) {
            throw new Error(
                `supported caller type = {X.509 | Vault-X.509 | 'WS-X.509'}, but provided : ${input}`,
            );
        }
        return true;
    }
}
