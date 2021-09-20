import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { UtilityEmissionsChannelV2 } from '../blockchain-gateway/utilityEmissionsChannel-v2';
import { Router, Request, Response } from 'express';
import { param, query, validationResult, body } from 'express-validator';
export interface IUtilityEmissionsChannelRouterOptions {
    logLevel: LogLevelDesc;
    utilityEmissionsChannel: UtilityEmissionsChannelV2;
}

export class UtilityEmissionsChannelRouterV2 {
    private readonly log: Logger;
    readonly className = 'UtilityEmissionsChannelRouterV2';
    readonly router: Router;
    constructor(private readonly opts: IUtilityEmissionsChannelRouterOptions) {
        this.log = LoggerProvider.getOrCreate({ label: this.className, level: opts.logLevel });
        this.router = Router();
        this.__registerHandlers();
    }

    private __registerHandlers() {
        this.router.post(
            '/recordEmissions',
            [
                query('callerType').custom((input) => this.__callerType(input)),
                body('utilityId').isString(),
                body('partyId').isString(),
                body('fromDate').custom((value) => {
                    const matches = value.match(
                        /^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(Z)?$/,
                    );
                    if (!matches) {
                        throw new Error(
                            'Date is required to be in ISO 6801 format (i.e 2016-04-06T10:10:09Z)',
                        );
                    }

                    // Indicates the success of this synchronous custom validator
                    return true;
                }),
                body('thruDate').custom((value) => {
                    const matches = value.match(
                        /^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(Z)?$/,
                    );
                    if (!matches) {
                        throw new Error(
                            'Date is required to be in ISO 6801 format (i.e 2016-04-06T10:10:09Z)',
                        );
                    }

                    // Indicates the success of this synchronous custom validator
                    return true;
                }),
                body('energyUseAmount').isNumeric(),
                body('energyUseUom').isString(),
            ],
            this.recordEmissions.bind(this),
        );

        this.router.get(
            '/getEmissionsData/:uuid',
            [
                query('callerType').custom((input) => this.__callerType(input)),
                param('uuid').isString(),
            ],
            this.getEmissionsData.bind(this),
        );
        this.router.get(
            '/getAllEmissionsData/:utilityId/:partyId',
            [
                query('callerType').custom((input) => this.__callerType(input)),
                param('utilityId').isString(),
                param('partyId').isString(),
            ],
            this.getAllEmissionData.bind(this),
        );
        this.router.get(
            '/getAllEmissionsDataByDateRange/:fromDate/:thruDate',
            [
                query('callerType').custom((input) => this.__callerType(input)),
                param('fromDate').isString(),
                param('thruDate').isString(),
            ],
            this.getAllEmissionsDataByDateRange.bind(this),
        );
    }

    private async recordEmissions(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        const token = (req as any).token;
        const username = (req as any).username;
        const callerType = req.query.callerType;
        const utilityId: string = req.body.utilityId;
        const partyId: string = req.body.partyId;
        const fromDate: string = req.body.fromDate;
        const thruDate: string = req.body.thruDate;
        const energyUseAmount: number = req.body.energyUseAmount as number;
        const energyUseUom: string = req.body.energyUseUom;
        let emissionsDoc: Buffer;
        if (req.file) {
            emissionsDoc = req.file.buffer;
        }
        try {
            await this.opts.utilityEmissionsChannel.recordEmissions(
                {
                    type: callerType as any,
                    username: username,
                    token: token,
                    sessionId: (req as any).sessionId,
                    signature: (req as any).signature, 
                },
                {
                    utilityId: utilityId,
                    partyId: partyId,
                    fromDate: fromDate,
                    thruDate: thruDate,
                    energyUseAmount: energyUseAmount,
                    energyUseUom: energyUseUom,
                    emissionsDoc: emissionsDoc,
                },
            );
            return res.sendStatus(201);
        } catch (error) {
            return res.status(409).json({
                msg: error.message,
            });
        }
    }
    private async getEmissionsData(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        const token = (req as any).token;
        const username = (req as any).username;
        const uuid = req.params.uuid;
        const callerType = req.query.callerType;
        try {
            const record = await this.opts.utilityEmissionsChannel.getEmissionsData(
                {
                    type: callerType as any,
                    username: username,
                    token: token,
                    sessionId: (req as any).sessionId, 
                    signature: (req as any).signature, 
                },
                uuid,
            );
            return res.status(200).json(record);
        } catch (error) {
            return res.status(409).json({
                msg: error.message,
            });
        }
    }
    private async getAllEmissionData(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        const token = (req as any).token;
        const username = (req as any).username;
        const utilityId = req.params.utilityId;
        const partyId = req.params.partyId;
        const callerType = req.query.callerType;
        try {
            const records = await this.opts.utilityEmissionsChannel.getAllEmissionRecords(
                {
                    type: callerType as any,
                    username: username,
                    token: token,
                    sessionId: (req as any).sessionId, 
                    signature: (req as any).signature, 
                },
                {
                    utilityId: utilityId,
                    partyId: partyId,
                },
            );
            return res.status(200).json(records);
        } catch (error) {
            return res.status(409).json({
                msg: error.message,
            });
        }
    }
    private async getAllEmissionsDataByDateRange(req: Request, res: Response) {
        const fnTag = `${req.method.toUpperCase()} ${req.originalUrl}`;
        this.log.info(fnTag);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            this.log.debug(`${fnTag} bad request : ${JSON.stringify(errors.array())}`);
            return res.status(400).json({
                msg: JSON.stringify(errors.array()),
            });
        }
        const token = (req as any).token;
        const username = (req as any).username;
        const fromDate = req.params.fromDate;
        const thruDate = req.params.thruDate;
        const callerType = req.query.callerType;
        try {
            const records = await this.opts.utilityEmissionsChannel.getAllEmissionsDataByDateRange(
                {
                    type: callerType as any,
                    username: username,
                    token: token,
                    sessionId: (req as any).sessionId, 
                    signature: (req as any).signature, 
                },
                {
                    fromDate: fromDate,
                    thruDate: thruDate,
                },
            );
            return res.status(200).json(records);
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
