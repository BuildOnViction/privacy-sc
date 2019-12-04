var PrivacyContract = artifacts.require("PrivacyCTV2");
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
const provider = new HDWalletProvider(privateKey, 'http://206.189.39.242:8545');

const web3 = new Web3(provider);


module.exports = function(deployer) {
    // deployer.deploy(RingCTVerifier).then((result) => {});
    deployer.deploy(PrivacyContract).then(async(result) => {
      console.log("result.address ", result.address);
      const issuerContract = await new web3.eth.Contract(
          ISSUER_ABI, issuer_address
      );

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
          console.log("Applied privacy to issuer")
        });
      } catch (ex) {
        console.log(ex);
      }
      console.log("DONE ");
    });
    
};