import { IdentityData } from '@zzocker/fabric-network';

export interface CertificateStore {
  get(key: string): Promise<IdentityData>;
  has(key: string): Promise<boolean>;
  put(key: string, identityData: IdentityData): Promise<void>;
}
