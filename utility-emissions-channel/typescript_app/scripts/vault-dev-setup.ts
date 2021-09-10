import Vault from 'node-vault';
import { readFileSync, writeFileSync } from 'fs';
import { EOL } from 'os';
import { join } from 'path';

const transitPath = 'dev-transit';
const secretPath = 'dev-secret';
const userpassPath = 'dev-userpass';
const clientPolicyName = 'dev-client';
const managerPolicyName = 'dev-manager';
const devToken = 'tokenId';
const devVaultEndpoint = 'http://localhost:8200';

// createPolicy
// enable userpass auth
// mountSecretPath
// mount transit path
const backend = Vault({
    endpoint: devVaultEndpoint,
    apiVersion: 'v1',
    token: devToken,
});

async function createPolicy(file: string, name: string): Promise<void> {
    const policy = readFileSync(join(__dirname, file)).toString();
    await backend.write('sys/policy/' + name, { policy: policy });
}

async function mountSecret(path: string, type: 'transit' | 'kv'): Promise<void> {
    await backend.write('sys/mounts/' + path, { type: type });
}

async function enableAuth(path: string, type: 'userpass') {
    await backend.write('sys/auth/' + path, { type: type });
}

async function updateEnv(): Promise<void> {
    const resp = await backend.read('sys/auth');
    const accessor = resp.data[userpassPath + '/'].accessor;
    const envPath = join(__dirname, '..', '.env');
    const envs = readFileSync(envPath, 'utf-8').split(EOL);
    const target = envs.indexOf(
        envs.find((line) => {
            return line.match(new RegExp('VAULT_IDENTITY_AUTH_USERPASS_ACCESSOR'));
        }),
    );
    envs.splice(target, 1, `VAULT_IDENTITY_AUTH_USERPASS_ACCESSOR='${accessor}'`);
    writeFileSync(envPath, envs.join(EOL));
}

(async () => {
    try {
        await Promise.all([
            createPolicy('./manager.hcl', managerPolicyName),
            createPolicy('./client-tmpl.hcl', clientPolicyName),
            mountSecret(transitPath, 'transit'),
            mountSecret(secretPath, 'kv'),
            enableAuth(userpassPath, 'userpass'),
            updateEnv(),
        ]);
    } catch (error) {
        console.log(error);
    }
})();
