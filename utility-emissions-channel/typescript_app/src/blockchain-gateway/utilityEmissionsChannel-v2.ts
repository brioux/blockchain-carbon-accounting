import { Logger, LoggerProvider, LogLevelDesc } from '@hyperledger/cactus-common';
import {
    FabricContractInvocationType,
    FabricSigningCredential,
    FabricSigningCredentialType,
    PluginLedgerConnectorFabric,
} from '@brioux/cactus-plugin-ledger-connector-fabric'

import { checkDateConflict } from './utils/dateUtils';
import {
    ICaller,
    IEmissionRecord,
    IUpdateEmissionsMintedTokenRequest,
} from './I-utilityEmissionsChannel';
import AWSS3 from './utils/aws';
import { createHash } from 'crypto';

export interface IUtilityEmissionsChannelV2Options {
    logLevel: LogLevelDesc;
    fabricConnector: PluginLedgerConnectorFabric;
    certStoredKeycahinId: string;
    dataStorage: AWSS3;
    orgName: string;
}

export class UtilityEmissionsChannelV2 {
    private readonly log: Logger;
    readonly className = 'UtilityEmissionsChannelV2';
    private readonly ccName = 'utilityemissions';
    private readonly channelName = 'utilityemissionchannel';
    constructor(private readonly opts: IUtilityEmissionsChannelV2Options) {
        this.log = LoggerProvider.getOrCreate({ label: this.className, level: opts.logLevel });
    }

    async recordEmissions(
        caller: ICaller,
        req: {
            utilityId: string;
            partyId: string;
            fromDate: string;
            thruDate: string;
            energyUseAmount: number;
            energyUseUom: string;
            emissionsDoc?: Buffer;
        },
    ): Promise<void> {
        const fnTag = `${this.className}#recordEmissions`;
        const signer = this.__signer(fnTag, caller);
        this.log.debug(`${fnTag} query ${this.ccName} chaincode installed on ${this.channelName}`);
        this.log.debug(`${fnTag} fetching all emissions with utilityId = ${req.utilityId}`);
        const emissionRecords = await this.getAllEmissionRecords(caller, {
            utilityId: req.utilityId,
            partyId: req.partyId,
        });
        this.log.debug(`${fnTag} overlap check of data between ${req.fromDate} to ${req.thruDate}`);
        for (const emission of emissionRecords) {
            const overlap: boolean = checkDateConflict(
                req.fromDate,
                req.thruDate,
                emission.fromDate,
                emission.thruDate,
            );
            if (overlap) {
                this.log.debug(
                    `${fnTag} Supplied dates ${req.fromDate} to ${req.thruDate} overlap with an existing dates ${emission.fromDate} to ${emission.thruDate}`,
                );
                throw new Error(
                    `Supplied dates ${req.fromDate} to ${req.thruDate} overlap with an existing dates ${emission.fromDate} to ${emission.thruDate}.`,
                );
            }
        }
        let url = '';
        let md5 = '';
        if (req.emissionsDoc) {
            this.log.debug(`${fnTag} uploading emissions docs to aws s3`);
            const filename = `${caller.username}-${this.opts.orgName}-${req.utilityId}-${req.partyId}-${req.fromDate}-${req.thruDate}.pdf`;
            this.log.debug(`${fnTag} upload ${filename} to S3`);
            try {
                const uploadResp = await this.opts.dataStorage.upload(req.emissionsDoc, filename);
                url = uploadResp.Location;
                md5 = createHash('md5').update(req.emissionsDoc).digest('hex');
            } catch (error) {
                this.log.debug(`${fnTag} failed to upload : %o`, error);
                throw new Error(`failed to upload : ${(error as Error).message}`);
            }
        }
        this.log.debug(`${fnTag} making invoke request to fabric`);
        try {
            await this.opts.fabricConnector.transact({
                signingCredential: signer,
                channelName: this.channelName,
                contractName: this.ccName,
                methodName: 'recordEmissions',
                invocationType: FabricContractInvocationType.Send,
                params: [
                    req.utilityId,
                    req.partyId,
                    req.fromDate,
                    req.thruDate,
                    `${req.energyUseAmount}`,
                    req.energyUseUom,
                    url,
                    md5,
                ],
            });
        } catch (error) {
            this.log.error(`${fnTag} failed to query chaincode : %o`, error);
            throw error;
        }
    }

    async getEmissionsData(caller: ICaller, uuid: string): Promise<IEmissionRecord> {
        const fnTag = `${this.className}#getEmissionsData`;
        const signer = this.__signer(fnTag, caller);
        this.log.debug(`${fnTag} query ${this.ccName} chaincode installed on ${this.channelName}`);
        let record: IEmissionRecord;
        try {
            const resp = await this.opts.fabricConnector.transact({
                signingCredential: signer,
                channelName: this.channelName,
                contractName: this.ccName,
                methodName: 'getEmissionsData',
                invocationType: FabricContractInvocationType.Call,
                params: [uuid],
            });
            if (resp.success) {
                record = JSON.parse(resp.functionOutput);
                if (record['class']) {
                    delete record['class'];
                }
            }
        } catch (error) {
            this.log.error(`${fnTag} failed to query chaincode : %o`, error);
            throw error;
        }
        await this.emissionsRecordChecksum(record);
        return record;
    }

    async getAllEmissionRecords(
        caller: ICaller,
        input: { utilityId: string; partyId: string },
    ): Promise<IEmissionRecord[]> {
        const fnTag = `${this.className}#getAllEmissionRecords`;
        const signer = this.__signer(fnTag, caller);
        this.log.debug(`${fnTag} query ${this.ccName} chaincode installed on ${this.channelName}`);
        let records: { key: string; Record: IEmissionRecord }[];
        try {
            const resp = await this.opts.fabricConnector.transact({
                signingCredential: signer,
                channelName: this.channelName,
                contractName: this.ccName,
                methodName: 'getAllEmissionsData',
                invocationType: FabricContractInvocationType.Call,
                params: [input.utilityId, input.partyId],
            });
            if (resp.success) {
                records = JSON.parse(resp.functionOutput);
            }
        } catch (error) {
            this.log.error(`${fnTag} failed to query chaincode : %o`, error);
            throw error;
        }
        const out: IEmissionRecord[] = [];
        for (const record of records) {
            delete record.Record['class'];
            await this.emissionsRecordChecksum(record.Record);
            out.push(record.Record);
        }
        return out;
    }

    async getAllEmissionsDataByDateRange(
        caller: ICaller,
        input: { fromDate: string; thruDate: string },
    ): Promise<IEmissionRecord[]> {
        const fnTag = `${this.className}#getAllEmissionsDataByDateRange`;
        const signer = this.__signer(fnTag, caller);
        this.log.debug(`${fnTag} query ${this.ccName} chaincode installed on ${this.channelName}`);
        let records: { key: string; Record: IEmissionRecord }[];
        try {
            const resp = await this.opts.fabricConnector.transact({
                signingCredential: signer,
                channelName: this.channelName,
                contractName: this.ccName,
                methodName: 'getAllEmissionsDataByDateRange',
                invocationType: FabricContractInvocationType.Call,
                params: [input.fromDate, input.thruDate],
            });
            if (resp.success) {
                records = JSON.parse(resp.functionOutput);
            }
        } catch (error) {
            this.log.error(`${fnTag} failed to query chaincode : %o`, error);
            throw error;
        }
        const out: IEmissionRecord[] = [];
        for (const record of records) {
            delete record.Record['class'];
            await this.emissionsRecordChecksum(record.Record);
            out.push(record.Record);
        }
        return out;
    }

    async updateEmissionsMintedToken(
        caller: ICaller,
        input: IUpdateEmissionsMintedTokenRequest,
    ): Promise<void> {
        const fnTag = `${this.className}#updateEmissionsMintedToken`;
        const signer = this.__signer(fnTag, caller);
        this.log.debug(`${fnTag} query ${this.ccName} chaincode installed on ${this.channelName}`);
        try {
            await this.opts.fabricConnector.transact({
                signingCredential: signer,
                channelName: this.channelName,
                contractName: this.ccName,
                methodName: 'updateEmissionsMintedToken',
                invocationType: FabricContractInvocationType.Send,
                params: [input.tokenId, input.partyId, ...input.uuids],
            });
        } catch (error) {
            this.log.error(`${fnTag} failed to query chaincode : %o`, error);
            throw error;
        }
    }
    private __signer(fnTag: string, caller: ICaller): FabricSigningCredential {
        this.log.debug(`${fnTag} caller = ${caller.username} , type = ${caller.type}`);
        const signer: FabricSigningCredential = {
            keychainId: this.opts.certStoredKeycahinId,
            keychainRef: caller.username,
            type: caller.type,
        };
        switch(signer.type) {
            case FabricSigningCredentialType.VaultX509:
                signer.vaultTransitKey = caller.vaultKey;
                break
            case FabricSigningCredentialType.WsX509:
                signer.webSocketKey = caller.webSocketKey
                break
        };
        return signer;
    }

    private async emissionsRecordChecksum(record: IEmissionRecord): Promise<void> {
        const fnTag = '#EmissionsRecordChecksum';
        if (record.url && record.url.length > 0) {
            const url = record.url;
            this.log.debug(`${fnTag} data at url = ${url}`);
            const filename = decodeURIComponent(url).split('/').slice(-1)[0];
            let data: Buffer;
            try {
                data = await this.opts.dataStorage.download(filename);
            } catch (error) {
                this.log.debug(`${fnTag} failed to fetch ${filename} from S3 : %o`, error);
                return;
            }

            this.log.debug(`${fnTag} data hash from blockchain = ${record.md5}`);
            const md5Sum = createHash('md5');
            md5Sum.update(data);
            if (md5Sum.digest('hex') !== record.md5) {
                throw new Error(
                    `The retrieved document ${record.url} has a different MD5 hash than recorded on the ledger. This file may have been tampered with.`,
                );
            }

            this.log.debug(`${fnTag} Md5 CheckSum successful !!`);
        }
    }
}
