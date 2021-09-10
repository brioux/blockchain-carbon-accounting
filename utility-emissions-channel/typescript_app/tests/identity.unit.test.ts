import { VaultIdentityBackend } from '../src/identity/backend';
import { config } from 'dotenv';
import { v4 as uuid4 } from 'uuid';
import asPromised from 'chai-as-promised';
import chai from 'chai';
/* eslint-disable @typescript-eslint/no-unused-vars */
const should = chai.should();
chai.use(asPromised);

config();

describe('vaultIdentityBackend', () => {
    const backend = new VaultIdentityBackend('DEBUG');
    const rootToken = 'tokenId';

    const managerUsername = 'manager-' + uuid4();
    const clientUsername = 'client-' + uuid4();
    const oldPassword = 'pw';
    const newPassword = 'newPw';

    it('should create manager identity', async () => {
        await backend.createManagerIdentity(rootToken, managerUsername, oldPassword);
    });

    let managerToken: string;
    it('should create manager token', async () => {
        managerToken = await backend.genToken(managerUsername, oldPassword);
        managerToken.should.be.string;
    });

    it('should create client identity', async () => {
        await backend.createClientIdentity(managerToken, clientUsername, oldPassword);
    });

    let clientToken: string;
    it('should create client token', async () => {
        clientToken = await backend.genToken(clientUsername, oldPassword);
        clientToken.should.be.string;
    });

    it('should get token details of manager', async () => {
        const details = await backend.tokenDetails(managerToken);
        details.username.should.be.equal(managerUsername);
    });

    it('should get token details of client', async () => {
        const details = await backend.tokenDetails(clientToken);
        details.username.should.be.equal(clientUsername);
    });

    it('should renew token of manager', async () => {
        await backend.renewToken(managerToken);
    });

    it('should renew token of client', async () => {
        await backend.renewToken(clientToken);
    });

    it('should update identity password of manager', async () => {
        await backend.updateIdentityPassword(managerToken, managerUsername, newPassword);
        managerToken = await backend.genToken(managerUsername, newPassword);
    });

    it('should update identity password of client', async () => {
        await backend.updateIdentityPassword(clientToken, clientUsername, newPassword);
        clientToken = await backend.genToken(clientUsername, newPassword);
    });

    {
        it('should create transit key for manager', async () => {
            await backend.createTransitKey(managerToken, managerUsername, 'ecdsa-p256');
        });

        it('throw if transit is created for other', () => {
            return (
                backend.createTransitKey(managerToken, clientUsername, 'ecdsa-p256') as any
            ).should.be.rejectedWith('permission denied');
        });

        it('should create transit key for client', async () => {
            await backend.createTransitKey(clientToken, clientUsername, 'ecdsa-p384');
        });

        it('throw if transit is created for other', () => {
            return (
                backend.createTransitKey(clientToken, managerUsername, 'ecdsa-p384') as any
            ).should.be.rejectedWith('permission denied');
        });
    }

    {
        it('should update kv for manager', async () => {
            await backend.setKVSecret(managerToken, managerUsername, {
                secret: 'manager-secret',
            });
        });

        it('throw if kv is update for other', () => {
            return (
                backend.setKVSecret(managerToken, clientUsername, {}) as any
            ).should.be.rejectedWith('permission denied');
        });

        it('should update kv for for client', async () => {
            await backend.setKVSecret(clientToken, clientUsername, { secret: 'client-secret' });
        });

        it('throw if kv is update for other', () => {
            return (
                backend.setKVSecret(clientToken, managerUsername, {}) as any
            ).should.be.rejectedWith('permission denied');
        });
    }

    {
        it('should read kv for manager', async () => {
            const secrets = await backend.getKVSecret(managerToken, managerUsername);
            secrets['secret'].should.be.equal('manager-secret');
        });

        it('throw if kv is read by other', () => {
            return (
                backend.getKVSecret(managerToken, clientUsername) as any
            ).should.be.rejectedWith('permission denied');
        });

        it('should read kv for client', async () => {
            const secrets = await backend.getKVSecret(clientToken, clientUsername);
            secrets['secret'].should.be.equal('client-secret');
        });

        it('throw if kv is read by other', () => {
            return (
                backend.getKVSecret(clientToken, managerUsername) as any
            ).should.be.rejectedWith('permission denied');
        });
    }
    it('should revoke token of manager', async () => {
        await backend.revokeToken(managerToken);
    });

    it('should revoke token of client', async () => {
        await backend.revokeToken(clientToken);
    });
});
