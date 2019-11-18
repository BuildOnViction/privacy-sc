var PrivacyContract = artifacts.require("PrivacyCTV2");
// var RingCTVerifier = artifacts.require("RingCTVerifier");
var Secp256k1 = artifacts.require("Secp256k1");
var SafeMath = artifacts.require("SafeMath");

const Web3 = require("web3");
const axios = require('axios');
const HDWalletProvider = require('truffle-hdwallet-provider');

// load single private key as string
const privateKey = "06E77C26DD44F807A67DCE660B8F8D39209100678DEEEFD032214B7BF0A99F02";
const address =  "0x1901deed3e1AfA53109DbA327B45B6F8Fa1809E1";
const issuer_address = '0x306e32d5a14cd4C433DC600C4A0b865b73b0b50A';

const ISSUER_ABI = [
  {
    "inputs": [
      {
        "name": "value",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "constructor",
    "signature": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "issuer",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "token",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "value",
        "type": "uint256"
      }
    ],
    "name": "Apply",
    "type": "event",
    "signature": "0x2d485624158277d5113a56388c3abf5c20e3511dd112123ba376d16b21e4d716"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "supporter",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "token",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "value",
        "type": "uint256"
      }
    ],
    "name": "Charge",
    "type": "event",
    "signature": "0x5cffac866325fd9b2a8ea8df2f110a0058313b279402d15ae28dd324a2282e06"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "minCap",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function",
    "signature": "0x3fa615b0"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "tokens",
    "outputs": [
      {
        "name": "",
        "type": "address[]"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function",
    "signature": "0x9d63848a"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "token",
        "type": "address"
      }
    ],
    "name": "getTokenCapacity",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function",
    "signature": "0x8f3a981c"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "token",
        "type": "address"
      }
    ],
    "name": "apply",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function",
    "signature": "0xc6b32f34"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "token",
        "type": "address"
      }
    ],
    "name": "charge",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function",
    "signature": "0xfc6bd76a"
  }
];

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