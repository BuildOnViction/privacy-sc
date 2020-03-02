var PrivacyContract = artifacts.require("TokenAnonymizer");
var MyPrivateToken = artifacts.require('MyPrivateToken');
const ANO = require('../build/contracts/TokenAnonymizer.json');
const TOKEN = require('../build/contracts/MyPrivateToken.json');
const editJsonFile = require("edit-json-file");
// var RingCTVerifier = artifacts.require("RingCTVerifier");
var Secp256k1 = artifacts.require("Secp256k1");
var SafeMath = artifacts.require("SafeMath");

const Web3 = require("web3");
const axios = require('axios');
const HDWalletProvider = require('truffle-hdwallet-provider');

const ENV = require("../env.json");

// load single private key as string
const privateKey = ENV.ACCOUNT.PRIVATEKEY;
const address = ENV.ACCOUNT.ADDRESS;
const issuer_address = ENV.ISSUER_ADDRESS;
const ISSUER_ABI = ENV.ISSUER_ABI;

// TODO move to config
const provider = new HDWalletProvider(privateKey, 'http://localhost:8545');

const web3 = new Web3(provider);

module.exports = async function(deployer) {
    var tokenAddress = '';
    const issuerContract = await new web3.eth.Contract(
      ISSUER_ABI, issuer_address
    );
    var privateTokenContract = await deployer.deploy(MyPrivateToken)
        .then(async(result) => {
          console.log('output token address = ', result.address);
          tokenAddress = result.address;

          try {
            await issuerContract.methods
              .apply(result.address)
              .send({
                from: address, // default from address
                value: '200000000000000000000',
                gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
                gas: '2000000'
              })
              .on('error', (error) => {
                console.log(error);
              })
              .then(() => {
                console.log("Applied Token privacy to issuer")
              });
          } catch (ex) {
            console.log(ex);
          }
          console.log("DONE Token!");
        });
  
    // deployer.deploy(RingCTVerifier).then((result) => {});
    await deployer.deploy(PrivacyContract, tokenAddress, true).then(async(anonymizer) => {
      console.log("anonymizer.address ", anonymizer.address);
      try {
        await issuerContract.methods
          .apply(anonymizer.address)
          .send({
            from: address, // default from address
            value: '200000000000000000000',
            gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
            gas: '2000000'
          })
          .on('error', (error) => {
            console.log(error);
          })
          .then(() => {
            console.log("Applied Anonymizer privacy to issuer");

            let file = editJsonFile(`${__dirname}/../../privacyjs/test/config.json`);
            file.set('TOKEN_ANONYMIZER_CONTRACT', anonymizer.address);
            file.set('TOKEN_ANONYMIZER_ABI', ANO.abi);
            file.set('TOKEN_CONTRACT', tokenAddress);
            file.set('TOKEN_ABI', TOKEN.abi);
            file.save();
          });
      } catch (ex) {
        console.log(ex);
      }
      console.log("DONE Anonymizer!");
    });
};