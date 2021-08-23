# ! /bin/bash

export PATH=${PWD}/bin_mac:${PWD}:$PATH
CC_NAME="basic-transfer"
CHANNEL_NAME=devchannel

function vendorChaincode(){
    if [ ! -d "chaincode/vendor" ];then
        docker run --rm \
        -v $PWD/chaincode:/tmp/chaincode \
        --name go-vender \
        golang:1.16 \
        /bin/sh -c 'cd /tmp/chaincode && go mod vendor'
    fi
}

function generateCrypto(){
    cryptogen generate --config crypto-config.yaml
    if [ $? != 0 ];then
        echo "failed to generate crypto"
        exit 1
    fi
    # fix private key of ca
    mv crypto-config/peerOrganizations/devorg.com/ca/*_sk crypto-config/peerOrganizations/devorg.com/ca/priv_sk
}

function generateArtifacts(){
    if [ ! -d "./artifacts" ];then
        mkdir ./artifacts
    fi

    configtxgen --outputBlock artifacts/genesis.block -channelID sys -profile Genesis
    if [ $? != 0 ];then
        echo "failed to generate genesis block"
        exit
    fi

    configtxgen -outputCreateChannelTx artifacts/chanenl.tx -profile DevChannel -channelID $CHANNEL_NAME
    if [ $? != 0 ];then
        echo "failed to generate create channel tx"
        exit
    fi
}

function joinChannel(){
    docker exec -it cli peer channel create -f /artifacts/chanenl.tx -c $CHANNEL_NAME -o orderer:7050 --outputBlock /tmp/devchannel.block
    if [ $? != 0 ];then
        echo "failed to create devchannel"
        exit 1
    fi
    echo ""
    echo ""
    echo "joinning devchannel"
    sleep 5
    docker exec -it cli peer channel join -b /tmp/devchannel.block
    if [ $? != 0 ];then
        echo "failed to join devchannel"
        exit 1
    fi
}


function installCC(){
    echo "installing chaincode"
    docker exec -it cli peer chaincode install -n $CC_NAME -p github.com/Zzocker/abc/chaincode -v 1
    if [ $? != 0 ];then
        echo "failed to install chaincode"
        exit
    fi
    echo "instantiating chaincode"
    docker exec -it cli peer chaincode instantiate -C $CHANNEL_NAME -n $CC_NAME -v 1 -c '{"args":[]}'
    if [ $? != 0 ];then
        echo "failed to instantiate chaincode"
        exit
    fi
    sleep 10
    docker exec -it cli peer chaincode invoke -C $CHANNEL_NAME -n basic-transfer -c '{"args" : ["InitLedger"]}' 
}


function cleanFolder(){
    rm -r crypto-config
    rm -r artifacts
}

function cleanDocker(){
    docker-compose down --volumes --remove-orphans
    docker rm -f $(docker ps -f "name=dev-*" -aq)
    docker image rm -f $(docker images dev-* -q) 
}

CMD=$1

case $CMD in
    "up")
        generateCrypto
        generateArtifacts
        vendorChaincode
        docker-compose up -d
        sleep 10
        joinChannel
        sleep 5
        installCC
    ;;

    "clean")
        cleanFolder
        cleanDocker
    ;;

    *)
        echo $CMD not supported
    ;;
esac