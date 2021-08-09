# /bin/bash
# should be executed before running any test
CMD=${1-prepare}

function setupVault(){
    # start dev vault server
    docker run --rm --name vault -d \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=tokenId' \
    -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' vault:1.8.1
    
    sleep 10
    # enable transit engine 
    docker exec -e VAULT_TOKEN=tokenId -e VAULT_ADDR=http://0.0.0.0:8200 -it vault vault secrets enable transit

    # create two key test-p256 , test-p384 , keyNotSupported for testing
    curl --header "X-Vault-Token: tokenId" --request POST --data '{"type" : "ecdsa-p256"}' http://127.0.0.1:8200/v1/transit/keys/test-p256
    curl --header "X-Vault-Token: tokenId" --request POST --data '{"type" : "ecdsa-p384"}' http://127.0.0.1:8200/v1/transit/keys/test-p384
    curl --header "X-Vault-Token: tokenId" --request POST --data '{"type" : "aes256-gcm96"}' http://127.0.0.1:8200/v1/transit/keys/keyNotSupported
}

case $CMD in
    "prepare")
        setupVault
    ;;
    "clean")
        docker rm -f vault
    ;;
    *)
        echo "$CMD not supported only {prepare|clean}"
        exit 1
    ;;
esac