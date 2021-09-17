// I-fabricRegistry-v2.ts : defines interface to enroll/register user
// with fabric ca.
//import { FabricSigningCredentialType } from '@hyperledger/cactus-plugin-ledger-connector-fabric';

import { 
    FabricSigningCredentialType,
    VaultKey,
    WebSocketKey
} from '@hyperledger/cactus-plugin-ledger-connector-fabric@0.9.1-web-socket-identity-provider.845e2a3e.23+845e2a3e';

export interface IRegistrarRequest {
    callerType: FabricSigningCredentialType;
    vaultKey?: VaultKey;
    webSocketKey?: WebSocketKey;
    //
    enrollmentID: string;
    role?: string;
    affiliation: string;
    maxEnrollments?: number;
    attrs?: { name: string; value: string; ecert?: boolean }[];
}

export interface IRegistrarResponse {
    enrollmentID: string;
    enrollmentSecret: string;
}
export interface IEnrollRequest {
    callerType: FabricSigningCredentialType;
    username: string;
    vaultKey?: VaultKey;
    webSocketKey?: WebSocketKey;
    secret?: string;
}
