#!/usr/bin/env node
import utils from './utils'

const yargs = require("yargs");
const options = yargs  
    .usage(utils.usage)  
    .option("k", {
        alias:"keys", 
        describe: "List all key names", 
        type: "boolean", 
        demandOption: false 
    })                                                                                                   
    .help(true)  
    .argv;

if(yargs.argv._[0] == null){  
    utils.showHelp();    
}else if(yargs.argv.k){
    utils.listKeys();
}else if(yargs.argv._[0]=='new-key'){
    utils.generateKey({keyName: yargs.argv._[1], curve: yargs.argv._[2]})
}else if(yargs.argv._[0]=='get-pkh'){
    console.log(utils.getPubKeyHex(yargs.argv._[1]))
}else if(yargs.argv._[0]=='connect'){
    utils.getClient(yargs.argv._[1],yargs.argv._[2],{keyName: yargs.argv._[3], curve: yargs.argv._[4]})
}