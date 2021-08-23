# /bin/bash
# should be executed before running any test
# and for doing development
CMD=${1-prepare}

function setupVault(){
    # start dev vault server
    docker run --rm --name vault -d \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=tokenId' \
    -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' vault:1.8.1

    #docker run -d --name=firefox \
    #-p 5800:5800 \
    #-v /Users/bertrandrioux/datas:/config:rw \
    #--shm-size 2g \
    #jlesage/firefox
    
    sleep 10
    # enable transit engine 
    docker exec -e VAULT_TOKEN=tokenId -e VAULT_ADDR=http://0.0.0.0:8200 -it vault vault secrets enable transit

    # create admin key test-p256 , test-p384 , keyNotSupported for testing
    curl --header "X-Vault-Token: tokenId" --request POST --data '{"type" : "ecdsa-p256"}' http://127.0.0.1:8200/v1/transit/keys/admin
    curl --header "X-Vault-Token: tokenId" --request POST --data '{"type" : "ecdsa-p256"}' http://127.0.0.1:8200/v1/transit/keys/test-p256
    curl --header "X-Vault-Token: tokenId" --request POST --data '{"type" : "ecdsa-p384"}' http://127.0.0.1:8200/v1/transit/keys/test-p384
    curl --header "X-Vault-Token: tokenId" --request POST --data '{"type" : "aes256-gcm96"}' http://127.0.0.1:8200/v1/transit/keys/keyNotSupported
}

function setupFabricWebSocketServer(){
    #cd test/web-socket-client/
    #if [ ! -d "node_modules" ];then
    #    npm i
    #fi
    #
    #if [ ! -d "dist" ];then
    #    npm run build
    #fi
    #npm run start
    #docker build . -t brioux/node-web-app
    #cd ../../

    docker run --rm --name web-socket-client -p 8500:8080 -d brioux/web-socket-client
}

case $CMD in
    "prepare")
        setupVault
        #setupFabricWebSocketServer
        # 
        # start test fabric network
        ##################################
        cd test/fabric-network/
        ./network.sh up
        cd ../..
        ##################################
    ;;
    "clean")
        docker rm -f vault
        docker rm -f web-socket-client
        # clean test fabric network
        ##################################
        cd test/fabric-network/
        ./network.sh clean
        cd ../..
        ##################################
    ;;
    *)
        echo "$CMD not supported only {prepare|clean}"
        exit 1
    ;;
esac