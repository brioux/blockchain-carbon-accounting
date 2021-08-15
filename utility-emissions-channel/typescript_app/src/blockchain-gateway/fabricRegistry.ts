// fabricRegistry.ts : interact with fabric-ca to enroll
// and register user
import {Logger, LoggerProvider, LogLevelDesc} from '@hyperledger/cactus-common';
import {PluginLedgerConnectorFabric} from '@hyperledger/cactus-plugin-ledger-connector-fabric';
import {IEnrollRegistrarRequest, IEnrollRegistrarResponse, 
    IEnrollUserRequest, IEnrollUserResponse, IStoreIdentityRequest} from './I-fabricRegistry';
//import {PluginKeychainVault} from '@hyperledger/cactus-plugin-keychain-vault';
import {LedgerKeychains} from './utils/LedgerKeychains'
import Client from 'fabric-client';
import { Wallets } from 'fabric-network'
//import {IdentityProvidersType} from '../../../../secure-fabric-provider/src/identityProviders'

export interface IFabricRegistryOptions{
    logLevel:LogLevelDesc;
    fabricClient:PluginLedgerConnectorFabric;
    orgCAs:{[key:string]:{
        mspId:string,
        ca:string
    }};
    //keychain:PluginKeychainVault;
    // offer keychain option from the LedgerKeychains class
    keychains:LedgerKeychains;
    adminUsername:string;
    adminPassword:string;
}

interface IX509Cert{
    type:string; // X509
    mspId:string;
    credentials?:{
        certificate:string;
        privateKey?:string;
        token?:string;
        keyname?:string;
    }
}

enum IdentityProvidersType {
  Default = 'Default-X.509',
  Vault = 'Vault-X.509'
}

export class FabricRegistry{
    static readonly CLASS_NAME = 'FabricRegistry';

    static readonly X509Type = 'X.509';
    static readonly X509Types = IdentityProvidersType

    private readonly log:Logger;
    get className():string{
        return FabricRegistry.CLASS_NAME;
    }

    constructor(private readonly opts:IFabricRegistryOptions){
        this.log = LoggerProvider.getOrCreate({level: opts.logLevel , label: this.className});
        const fnTag = `#constructor`;
        this.log.debug(`${fnTag} orgCAs : %o`,opts.orgCAs);
    }

    async enrollRegistrar(req:IEnrollRegistrarRequest):Promise<IEnrollRegistrarResponse>{
        const fnTag = '#enrollRegistrar';
        try {
            const keychainType = req.keychainType;
            const key = `${req.orgName}_${this.opts.adminUsername}`
            console.log(key);
            if (await this.opts.keychains[`${req.keychainType}`].has(key)){
                throw new Error(`${this.opts.adminUsername} of organization ${req.orgName} is already enrolled`);
            }
            const refCA = this.opts.orgCAs[req.orgName];
            console.log(refCA);
            this.log.debug(`${fnTag} enroll ${req.orgName}'s registrar with ${refCA.ca}`);
            const ca = await this.opts.fabricClient.createCaClient(refCA.ca);
            const enrollment = await ca.enroll({ 
              enrollmentID: this.opts.adminUsername,
              enrollmentSecret: this.opts.adminPassword,
              csr: req.csr
            });
            await this.storeIdentity({
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
                keychainType,
                key,
                mspId: refCA.mspId,
                fnTag
            });
            return {
                orgName: req.orgName,
                msp : refCA.mspId,
                caName : ca.getCaName(),
                info: 'ORG ADMIN REGISTERED'
            };
        } catch (error) {
            throw error;
        }
    }

    async enrollUser(req:IEnrollUserRequest):Promise<IEnrollUserResponse>{
        const fnTag = '#registerUser';
        const key = `${req.orgName}_${req.userId}`;
        const keychainType = req.keychainType
        const keychain = await this.opts.keychains[keychainType];
        const csr = req.csr;
        try {
            if (await keychain.has(key)){
                throw new Error(`${req.userId} of organization ${req.orgName} is already enrolled`);
            }
            const refCa = this.opts.orgCAs[req.orgName];
            if (!refCa){
                throw new Error(`organization ${req.orgName} doesn't exist`);
            }
            // TO-DO this should be customized based on the keychain used by the organizations admin
            // For now this defaults to Vault.
            const adminKeychain = this.opts.keychains.Vault;
            const adminKey = `${req.orgName}_${this.opts.adminUsername}`
            const rawAdminCerts:string = await adminKeychain.get(adminKey);
            if (!rawAdminCerts){
                throw new Error(`${req.orgName}'s admin is not enrolled, please enroll admin first`);
            }

            const adminCerts = JSON.parse(rawAdminCerts);
            // register user
            // build admin user
            this.log.debug(`${fnTag} building admin user`);
            /*
            
            const builder = new Client();

            const admin = await builder.createUser({
                username:this.opts.adminUsername,
                mspid : refCa.mspId,
                skipPersistence: true,
                cryptoContent : {
                    privateKeyPEM : adminCerts.privateKey,
                    signedCertPEM : adminCerts.certificate
                }
            });*/
            const wallet = await Wallets.newInMemoryWallet();
            wallet.put(adminKey, adminCerts);

            const provider = wallet.getProviderRegistry().getProvider(adminCerts.type);
            const admin = await provider.getUserContext(adminCerts, adminKey);

            const ca = await this.opts.fabricClient.createCaClient(refCa.ca);
            this.log.debug(`${fnTag} registering ${req.userId}`);
            console.log(req);
            const secret = await ca.register({
                enrollmentID: req.userId,
                affiliation: req.affiliation,
                role: 'client'
            },admin);

            this.log.debug(`${fnTag} enrolling ${req.userId}`);
            const enrollment = await ca.enroll({ 
                enrollmentID: req.userId,
                enrollmentSecret: secret,
                csr
            });
            await this.storeIdentity({
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
                keychainType,
                key,
                csr, 
                mspId: refCa.mspId,
                fnTag
            }) 
            this.log.debug(`${fnTag} ${req.userId} successfully enrolled`);
            return {
                orgName: req.orgName,
                msp : refCa.mspId,
                caName : ca.getCaName(),
                info: 'USER REGISTERED AND ENROLLED'
            };
        } catch (error) {
            throw error;
        }
    }

    async storeIdentity(req:IStoreIdentityRequest){
        try {
            const keychainType = req.keychainType;
            // store the private key if CST was generated during the registration stage.
            let identity:IX509Cert;
            if(req.csr){
                if(keychainType == 'Vault'){
                    identity = {
                        type: IdentityProvidersType[keychainType],
                        credentials: {
                            certificate: req.certificate,
                            keyname: '',
                            token: 'tokenId'
                        },
                        mspId: req.mspId
                    }; 
                }               
            }else{
                identity = {
                    type: FabricRegistry.X509Type,
                    credentials: {
                        certificate: req.certificate,
                        privateKey: req.privateKey
                    },
                    mspId: req.mspId,
                };
            }
            const keychain = this.opts.keychains[`${req.keychainType}`];
            this.log.debug(`${req.fnTag} storing certificate inside ${req.keychainType} keychain`);
            await keychain.set(req.key,JSON.stringify(identity));
        } catch (error) {
            throw error;
        }
    }
}