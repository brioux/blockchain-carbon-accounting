import {IdentityProvider,Identity,IdentityData} from '@zzocker/fabric-network'
import {IdentityProvidersType} from './identityProviders'

export interface VaultX509Identity extends Identity{
    type: IdentityProvidersType.Vault,
    credentials:{
        certificate:string
        keyName:string
        vaultToken:string
    }
}

export interface VaultX509IdentityData extends IdentityData{
    
}