# Net Emissions Tokens Network

The net emissions tokens network represents the net emissions of an entity, which could be an organization, a building, or even a person. It is the sum of all the emissions from different channels such as the [utility emissions channel](https://wiki.hyperledger.org/display/CASIG/Utility+Emissions+Channel), plus offsetting Renewable Energy Certificates and carbon offsets. Each token represents either an emissions debt, which you incur through activities that emit greenhouse gases, or an emissions credit, which offset the debt by removing emissions from the atmosphere.

Read more on the [Hyperledger Climate Action SIG website](https://wiki.hyperledger.org/display/CASIG/Net+Emissions+Tokens+Network).

## Contracts

The net emissions token network is implemented as a ERC-1155 multi-token smart contract compatible on any EVM-compatible blockchain. [Hardhat](https://hardhat.org) is the Ethereum development environment used to compile, deploy, test, and debug contracts.

### Installation and use

- First, install Hardhat globally with `npm install --save-dev hardhat`
- Clone this repository, navigate to the net-emissions-token-network directory, and run `npm install`
- To test, run `npx hardhat test`
- To compile, run `npx hardhat compile`
- To see all commands, run `npx hardhat`

## Interface

The interface is created using [create-eth-app](https://github.com/PaulRBerg/create-eth-app).

### Installation and use

- To install, clone this repository, navigate to the net-emissions-token-network/interface directory, and run `yarn install`
- To run on your local environment, run `yarn react-app:start`
- To build, run `yarn react-app:build`

### Connecting to local testnet

Hardhat implements its own Ethereum local testnet called Hardhat Network. In order to connect the interface to this local testnet:

1. Install the [MetaMask extension](https://metamask.io/)
2. Run the interface in `net-emissions-token-network/interface` with `yarn react-app:start`
3. In a separate terminal, run the Hardhat Network in `net-emissions-token-network` with `npx hardhat node`
4. In another separate terminal, deploy the contracts to the local Hardhat Network with `npx hardhat run --network localhost scripts/deploy.js`
5. Back in the interface, press _Connect Wallet_ to connect to your MetaMask wallet
6. In the MetaMask extension, change the network from Ethereum Mainnet to _Localhost 8545_

You should now be connected to your local testnet and be able to interact with contracts deployed on it.

### Token User Flow

In the net-emissions-token-network contract, we currently support this functionality:

- Defining a new token
- Minting this token and verifying that it's type is valid
- Registering/unregistering dealers
- Registering/unregistering consumers
- Transferring tokens
- Retiring tokens

#### An example of a user consuming these services would look similar to the following:

Using the contract owner, register a new dealer. The registerDealer function expects the following arguments:

```bash
function registerDealer( address account )
```

A dealer can consume all services within the contract. In order to allow a dealer's customers or consumers to be issued a token, they must be first registered. The registerConsumer function expects the following:

```bash
function registerConsumer( address account )
```

After registering a consumer, the dealer will be able to issue this consumer a token with the issue function:

```bash
function issue( address account, uint256 tokenId, uint256 quantity, string memory uom, string memory fromDate, string memory thruDate, string memory metadata, string memory manifest, string memory automaticRetireDate )
```

Dealers and consumers may also be unregistered within the network. Only the contract owner can unregister a dealer:

```bash
function unregisterDealer( address account )
```

A dealer may unregister its consumers with the unregisterConsumer function:

```bash
function unregisterConsumer( address account )
```

#### Testing the contract in remix

For interacting with the contract in development, the current solution is to use the Remix IDE.

First, the remixd plugin must be installed globally via NPM to create a volume from your local machine to Remix in browser.

```bash
npm install -g remixd
```

If you have not already, make sure Hardhat is installed globally to your machine (see above) and install the dependencies for the contract in the net-emissions-token-network directory:

```bash
npm install
```

To start the volume, run the following from the root directory of this repo:

```bash
remixd -s ./net-emissions-token-network --remix-ide https://remix.ethereum.org
```

After installing, navigate to https://remix.ethereum.org/ in the browser of your choice. (Currently only tested in Chrome)

Find the "plugins" tab on the left of the IDE user interface. Select remixd and connect. You will now see the entire net-emissions-token-network folder in the file explorer within remixd.

Under localhost -> contracts, select NetEmissionsTokenNetwork.sol in the file explorer.

Go to the compiler tab, change the compiler version to 0.6.2, and compile the contract.

Next, select the "Deploy and run transactions tab", change the gas limit to "9999999", select "NetEmissionsTokenNetwork" from the drop down, and deploy the contract.

You can now interact with the contract's functions via the user interface in Remix.