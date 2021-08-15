// I-fabricRegistry.ts : defines interface to enroll/register user
// with fabric ca.
import FabricCAServices from "fabric-ca-client";

export interface IEnrollRegistrarRequest{
    orgName:string;
    keychainType:string;
    csr?:string;
}

export interface IEnrollRegistrarResponse{
    info:string;
    orgName:string;
    msp:string;
    caName:string;
}


export interface IEnrollUserRequest{
    orgName:string;
    userId:string;
    affiliation:string;
    keychainType:string;
    csr?:string;
}

export interface IEnrollUserResponse{
    info:string;
    orgName:string;
    msp:string;
    caName:string;
}

export interface IStoreIdentityRequest{
    certificate:string;
    privateKey?:string;
    csr?:string;
    keychainType:string;
    key:string;
    mspId:string;
    fnTag:string;
}