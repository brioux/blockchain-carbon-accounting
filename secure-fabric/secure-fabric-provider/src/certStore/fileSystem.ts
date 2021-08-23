import { ICertDatastore } from './certStore';
import { Util } from '../internal/util';
import { IIdentityData } from '../identity';
import { join } from 'path';
import { existsSync, mkdirSync, readFile as read, writeFile as write, exists as FileExists } from 'fs';
import { promisify } from 'util';

const readFile = promisify(read);
const writeFile = promisify(write);
const exists = promisify(FileExists);

export interface IFileCertStoreOpts {
  folderPath: string;
}

export class FileCertStore implements ICertDatastore {
  private readonly folderPath: string;
  constructor(opts: IFileCertStoreOpts) {
    if (Util.isEmptyString(opts.folderPath)) {
      throw new Error('require non-empty cert store folder');
    }
    if (!existsSync(opts.folderPath)) {
      mkdirSync(opts.folderPath);
    }
    this.folderPath = opts.folderPath;
  }
  async has(key: string): Promise<boolean> {
    return await exists(this._getFilename(key));
  }
  async get(key: string): Promise<IIdentityData> {
    const raw = await readFile(this._getFilename(key), 'utf-8');
    if (Util.isEmptyString(raw)) {
      throw new Error('certificate not found in cert datastore');
    }
    return JSON.parse(raw) as IIdentityData;
  }
  async put(iData: IIdentityData): Promise<void> {
    const raw = JSON.stringify(iData, null, 4);
    await writeFile(this._getFilename(iData.key), raw);
  }

  private _getFilename(key: string): string {
    return join(this.folderPath, key + '.json');
  }
}
