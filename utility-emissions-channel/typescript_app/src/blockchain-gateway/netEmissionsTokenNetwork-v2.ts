import { Logger, LoggerProvider, LogLevelDesc, Checks } from '@hyperledger/cactus-common';
import {
    PluginLedgerConnectorXdai,
    Web3SigningCredential,
    Web3SigningCredentialType,
    InvokeContractV1Response,
    EthContractInvocationType,
} from '@hyperledger/cactus-plugin-ledger-connector-xdai';
import contractABI from '../contracts/NetEmissionsTokenNetwork.json';
import Web3 from 'web3';
import { IEthCaller, IIssueRequest, IIssueResponse } from './I-netEmissionsTokenNetwork';
import { VaultIdentityBackend } from '../identity/backend';

export interface INetEmissionsTokenNetworkContractOptions {
    logLevel: LogLevelDesc;
    ethConnector: PluginLedgerConnectorXdai;
    contractName: string;
    contractAddress: string;
    contractStorekeychainID: string;
    vaultBackend?: VaultIdentityBackend;
}

export class NetEmissionsTokenNetworkContractV2 {
    private readonly log: Logger;
    private readonly EventTokenCreatedInput: any[];
    private readonly tokenTypeId = 3;
    readonly className = 'NetEmissionsTokenNetworkContractV2';
    private readonly web3: Web3;
    constructor(private readonly opts: INetEmissionsTokenNetworkContractOptions) {
        const fnTag = `${this.className}#constructor`;
        this.log = LoggerProvider.getOrCreate({ label: this.className, level: opts.logLevel });
        const tokenCreatedABI = contractABI.abi.find((value) => {
            return value.type === 'event' && value.name === 'TokenCreated';
        });
        Checks.truthy(tokenCreatedABI, `${fnTag} tokenCreated event abi`);
        this.EventTokenCreatedInput = tokenCreatedABI.inputs;
        // web3 for decoding log messages
        this.web3 = new Web3();
    }

    async issue(caller: IEthCaller, token: IIssueRequest): Promise<IIssueResponse> {
        const fnTag = `${this.className}`;
        const signer = await this.__signer(fnTag, caller);
        this.log.debug(`${fnTag} invoking ethereum token`);
        let result: InvokeContractV1Response;
        try {
            const automaticRetireDate = +token.automaticRetireDate.toFixed();
            result = await this.opts.ethConnector.invokeContract({
                contractName: this.opts.contractName,
                signingCredential: signer,
                invocationType: EthContractInvocationType.Send,
                methodName: 'issue',
                params: [
                    token.addressToIssue,
                    this.tokenTypeId,
                    token.quantity,
                    token.fromDate,
                    token.thruDate,
                    automaticRetireDate,
                    token.metadata,
                    token.manifest,
                    token.description,
                ],
                keychainId: this.opts.contractStorekeychainID,
            });
        } catch (error) {
            this.log.error(`${fnTag} failed to invoke ethereum contract : %o`, error);
            throw error;
        }
        if (!result.success) {
            throw new Error(`failed to invoke ${this.opts.contractName}`);
        }
        const txReceipt = result['out'].transactionReceipt;
        // decode logs to get readable format
        const logData = txReceipt.logs[2];
        const hexString = logData.data;
        const topics = logData.topics;
        const tokenCreatedDecoded = this.web3.eth.abi.decodeLog(
            this.EventTokenCreatedInput,
            hexString,
            topics,
        );
        this.log.debug(`${fnTag} result = %o`, tokenCreatedDecoded);

        return {
            tokenId: `${this.opts.contractAddress}:${tokenCreatedDecoded.tokenId}`,
        };
    }

    private async __signer(fnTag: string, caller: IEthCaller): Promise<Web3SigningCredential> {
        if (caller.key) {
            return {
                type: Web3SigningCredentialType.PrivateKeyHex,
                ethAccount: caller.key.address,
                secret: caller.key.private,
            };
        } else if (caller.token) {
            this.log.debug(`${fnTag} fetching ethereum key from vault`);
            const secret = await this.opts.vaultBackend.getKVSecret(caller.token, caller.username);
            if (!secret['ETHEREUM_KEY']) {
                throw new Error(`${fnTag} ethereum key not found in vault`);
            }
            const key = JSON.parse(secret['ETHEREUM_KEY']);
            return {
                type: Web3SigningCredentialType.PrivateKeyHex,
                ethAccount: key.address,
                secret: key.private,
            };
        }
    }
}
