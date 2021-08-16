import { IIdentityData } from '../identity';


export interface ICertDatastore {
  has(key: string): Promise<boolean>;
  get(key: string): Promise<IIdentityData>;
  put(iData: IIdentityData): Promise<void>;
}
