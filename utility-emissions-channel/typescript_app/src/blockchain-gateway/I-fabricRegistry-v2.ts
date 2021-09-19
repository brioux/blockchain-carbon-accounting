// I-fabricRegistry-v2.ts : defines interface to enroll/register user
// with fabric ca.

import { 
    FabricSigningCredentialType,
    VaultTransitKey,
    WebSocketKey
} from '@brioux/cactus-plugin-ledger-connector-fabric';

export interface IRegistrarRequest {
    callerType: FabricSigningCredentialType;
    username: string;
    vaultKey?: VaultTransitKey;
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
    vaultKey?: VaultTransitKey;
    webSocketKey?: WebSocketKey;
    secret?: string;
}
