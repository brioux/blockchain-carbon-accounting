// I-fabricRegistry-v2.ts : defines interface to enroll/register user
// with fabric ca.
import { FabricSigningCredentialType } from '@hyperledger/cactus-plugin-ledger-connector-fabric';

export interface IRegistrarRequest {
    callerType: FabricSigningCredentialType;
    username: string;
    token: string;

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
    token: string;
    secret?: string;
}
