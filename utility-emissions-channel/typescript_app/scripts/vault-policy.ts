// vault-policy.ts cli for generating vault policy
import { writeFileSync } from 'fs';
import { join } from 'path';

function client(transit: string, secret: string, userpass: string): void {
    const policy = `path "${transit}/keys/{{identity.entity.name}}"{
        capabilities = [ "create", "update", "read", "delete", "list" ]
    }
    
    # For signing
    path "${transit}/sign/{{identity.entity.name}}"{
        capabilities = [ "update" ]
    }
    
    # For key Rotate
    path "${transit}/keys/{{identity.entity.name}}/rotate"{
        capabilities = [ "update" ]
    }
    
    
    path "${secret}/data/{{identity.entity.name}}"{
        capabilities = [ "create", "update", "read", "delete", "list" ]
    }
    
    # For changing password
    path "auth/${userpass}/users/{{identity.entity.name}}/password"{
        capabilities = [ "update" ]   
    }
    
    # For Web UI usage
    path "${secret}/metadata" {
      capabilities = ["list","read"]
}
`;
    const policyPath = join(__dirname, 'client-tmpl.hcl');
    writeFileSync(policyPath, policy);
}

function manager(transit: string, secret: string, userpass: string): void {
    const policy = `path "${transit}/keys/{{identity.entity.name}}"{
        capabilities = [ "create", "update", "read", "delete", "list" ]
    }
    
    # For signing
    path "${transit}/sign/{{identity.entity.name}}"{
        capabilities = [ "update" ]
    }
    
    path "${secret}/data/{{identity.entity.name}}"{
        capabilities = [ "create", "update", "read", "delete", "list" ]
    }
    
    # For Web UI usage
    path "${secret}/metadata" {
      capabilities = ["list","read"]
    }
    
    # For changing password
    path "auth/${userpass}/users/{{identity.entity.name}}/password"{
        capabilities = [ "update" ]   
    }
    
    # for creating user pass auth for client
    path "auth/${userpass}/users/*"{
        capabilities = [ "create" ]   
    }
    
    # for creating entity for client
    path "identity/entity"{
        capabilities = [ "update" ]   
    }
    
    # for creating entity alias for client
    path "identity/entity-alias"{
        capabilities = [ "update" ]   
    }`;
    const policyPath = join(__dirname, 'manager.hcl');
    writeFileSync(policyPath, policy);
}

const args = process.argv.splice(2);
if (args.length !== 3) {
    console.log(
        `Require 3 argument\n\ttransitPath\n\tsecretPath\n\tuserpassPath\nBut Provided ${args}`,
    );
    process.exit(1);
}

client(args[0], args[1], args[2]);
manager(args[0], args[1], args[2]);
