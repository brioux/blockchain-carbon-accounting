import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import { UtilityEmissionsChannelV2 } from '../blockchain-gateway/utilityEmissionsChannel-v2';
import { NetEmissionsTokenNetworkContractV2 } from '../blockchain-gateway/netEmissionsTokenNetwork-v2';
import { Request, Response, Router } from 'express';
import { IEmissionRecord, ICaller } from '../blockchain-gateway/I-utilityEmissionsChannel';
import { query, body, header, validationResult } from 'express-validator';

import { 
    FabricSigningCredentialType,
} from '@brioux/cactus-plugin-ledger-connector-fabric'

import { toTimestamp } from '../blockchain-gateway/utils/dateUtils';
import { IEthCaller } from '../blockchain-gateway/I-netEmissionsTokenNetwork';
export interface ICarbonAccountingRouterV2Options {
    logLevel: LogLevelDesc;
    netEmissionsTokenContract: NetEmissionsTokenNetworkContractV2;
    utilityEmissionChannel: UtilityEmissionsChannelV2;
    orgName: string;
}
export class CarbonAccountingRouterV2 {
    readonly className = 'CarbonAccountingRouterV2';
    private readonly log: Logger;
    public readonly router: Router;
    constructor(private readonly opts: ICarbonAccountingRouterV2Options) {
        this.log = LoggerProvider.getOrCreate({ level: opts.logLevel, label: this.className });
        this.router = Router();
        this.___registerHandlers();
    }

    private ___registerHandlers() {
        this.router.post(
            '/recordAuditedEmissionsToken',
            [
                query('callerType').custom((input) => this.__callerType(input)),
                body('partyId').isString(),
                body('addressToIssue').isString(),
                body('emissionsRecordsToAudit').isString(),
                header('ethAddress').isHexadecimal().optional(),
                header('ethPrivate').isHexadecimal().optional(),
                query('automaticRetireDate').isString().optional(),
            ],
            this.recordAuditedEmissionsToken.bind(this),
        );
    }
    private async recordAuditedEmissionsToken(req: Request, res: Response) {
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
        const vaultKey = (req as any).vaultKey;
        const webSocketKey = (req as any).webSocketKey        
        const callerType = req.query.callerType;
        const partyId = req.body.partyId;
        const caller: ICaller = {
            token: token,
            username: username,
            type: callerType as FabricSigningCredentialType,
            vaultKey: vaultKey,
            webSocketKey: webSocketKey,
        };
        const ethCaller: IEthCaller = {
            username: username,
            token: token,
        };
        if (req.header('ethAddress')) {
            ethCaller.key = {
                address: req.header('ethAddress'),
                private: req.header('ethPrivate'),
            };
        }
        let automaticRetireDate = req.query.automaticRetireDate as string;
        const re = new RegExp(
            /^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(Z)?$/,
        );
        if (!re.test(automaticRetireDate)) {
            automaticRetireDate = new Date().toISOString();
        }
        const emissionsRecordsToAudit = req.body.emissionsRecordsToAudit.toString().split(',');
        this.log.debug(`${fnTag} fetching emissionRecord uuids=%o`, emissionsRecordsToAudit);

        const metadata: any = {};
        metadata.org = this.opts.orgName;
        metadata.type = 'Utility Emissions';
        metadata.partyId = [];
        metadata.renewableEnergyUseAmount = 0;
        metadata.nonrenewableEnergyUseAmount = 0;
        metadata.utilityIds = [];
        metadata.factorSources = [];
        metadata.urls = [];
        metadata.md5s = [];
        metadata.fromDates = [];
        metadata.thruDates = [];

        let quantity = 0;
        const manifestIds = []; // stores uuids

        let fromDate = Number.MAX_SAFE_INTEGER;
        let thruDate = 0;
        const fetchedEmissionsRecords: IEmissionRecord[] = []; // stores fetched emissions records for updating tokenId on fabric after auditing
        // connect to fabric , request type : call
        // fetches details of emissionRecords with given uuids
        for (const uuid of emissionsRecordsToAudit) {
            let emission: IEmissionRecord;
            try {
                emission = await this.opts.utilityEmissionChannel.getEmissionsData(caller, uuid);
                fetchedEmissionsRecords.push(emission);
            } catch (error) {
                this.log.debug(`${fnTag} failed to fetch ${uuid} : %o`, error);
                continue;
            }
            if (emission.tokenId !== null) {
                const tokenIdSplit = emission.tokenId.split(':');
                this.log.debug(
                    `${fnTag} skipping emission Record with id = ${uuid},already audited to token ${tokenIdSplit[1]} on contract ${tokenIdSplit[0]}`,
                );
                continue;
            }

            // check  timestamps to find overall rang of dates later
            const fetchedFromDate = toTimestamp(emission.fromDate);
            if (fetchedFromDate < fromDate) {
                fromDate = fetchedFromDate;
            }
            const fetchedThruDate = toTimestamp(emission.thruDate);
            if (fetchedThruDate > thruDate) {
                thruDate = fetchedThruDate;
            }

            if (emission.fromDate !== '' && emission.thruDate !== '') {
                metadata.fromDates.push(emission.fromDate);
                metadata.thruDates.push(emission.thruDate);
            }
            if (!metadata.utilityIds.includes(emission.utilityId)) {
                metadata.utilityIds.push(emission.utilityId);
            }
            if (!metadata.partyId.includes(emission.partyId)) {
                metadata.partyId.push(emission.partyId);
            }
            if (!metadata.factorSources.includes(emission.factorSource)) {
                metadata.factorSources.push(emission.factorSource);
            }
            if (emission.md5 !== '') {
                metadata.md5s.push(emission.md5);
            }
            if (emission.url !== '') {
                metadata.urls.push(emission.url);
            }
            metadata.renewableEnergyUseAmount += emission.renewableEnergyUseAmount;
            metadata.nonrenewableEnergyUseAmount += emission.nonrenewableEnergyUseAmount;

            const qnt: number = +emission.emissionsAmount.toFixed(3);
            quantity += qnt * 1000;
            manifestIds.push(emission.uuid);
        }
        this.log.debug(`${fnTag} %o`, metadata);
        if (metadata.utilityIds.length === 0) {
            this.log.info(`${fnTag} no emissions records found; nothing to audit`);
            return res.status(404).json({
                msg: 'no emissions records found; nothing to audit',
            });
        }
        // TODO : read form env
        // const URL =
        const manifest =
            'URL: https://utilityemissions.opentaps.net/api/v1/utilityemissionchannel, UUID: ' +
            manifestIds.join(', ');
        this.log.debug(`${fnTag} quantity ${quantity}`);
        const addressToIssue = req.body.addressToIssue;
        this.log.debug(`${fnTag} minting emission token`);
        // connect to ethereum , request type : send
        // mint emission token on ethereum
        let tokenId: string;
        const description = 'Audited Utility Emissions';
        try {
            const token = await this.opts.netEmissionsTokenContract.issue(ethCaller, {
                addressToIssue,
                quantity,
                fromDate,
                thruDate,
                automaticRetireDate: toTimestamp(automaticRetireDate),
                metadata: JSON.stringify(metadata),
                manifest,
                description,
            });
            tokenId = token.tokenId;
            this.log.debug(`${fnTag} minted token ${token.tokenId}`);
        } catch (error) {
            this.log.info(`${fnTag} failed to mint audited emission token : ${error}`);
            return res.status(500).json({
                msg: error.message,
            });
        }
        // connect to fabric , request type : send
        // update all emissionRecords with minted tokenId
        try {
            await this.opts.utilityEmissionChannel.updateEmissionsMintedToken(caller, {
                tokenId: tokenId,
                partyId: partyId,
                uuids: manifestIds,
            });
        } catch (error) {
            this.log.debug(`${fnTag} failed to update emission record %o`, error);
            return res.status(500).json({
                msg: error.message,
            });
        }
        return res.status(201).json({
            info: 'AUDITED EMISSIONS TOKEN RECORDED',
            tokenId,
            quantity,
            fromDate,
            thruDate,
            automaticRetireDate,
            metadata,
            manifest,
            description,
        });
    }
    private __callerType(input): boolean {
        if (!['X.509', 'Vault-X.509','WS-X.509'].includes(input)) {
            throw new Error(
                `supported caller type = {X.509 | Vault-X.509 | 'WS-X.509'}, but provided : ${input}`,
            );
        }
        return true;
    }
}
