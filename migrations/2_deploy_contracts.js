var PrivacyContract = artifacts.require("PrivacyCT");
var Secp256k1 = artifacts.require("Secp256k1");
var SafeMath = artifacts.require("SafeMath");
const axios = require('axios');

async function verifyContractOnScan(contractAddress, contractName, fullcode) {
  return await axios.post('https://scan.testnet.tomochain.com/api/contracts', {
    "contractAddress": contractAddress,
    "contractName": contractName,
    "sourceCode": fullcode,
    "version": 2,
    "optimization": 1
  });
}

async function deployContracts() {

}

async function flattenContract() {
  const util = require('util');
  const exec = util.promisify(require('child_process').exec);

  async function flatten() {
    const { stdout, stderr } = await exec('truffle-flattener ../contracts/PrivacyCT.sol');
    // console.log('stdout:', stdout);
    // console.log('stderr:', stderr);

    return stdout;
  }
  return await flatten();
}

module.exports = function(deployer) {
    // deployer.deploy(Secp256k1);
    // deployer.deploy(SafeMath);
    // deployer.link(Secp256k1, PrivacyContract);
    // deployer.link(SafeMath, PrivacyContract);
    return deployer.deploy(PrivacyContract).then(async (result) => {
      // verify the contract to test net example
      try {
        let smartContractAddress = result.address;
        console.log(smartContractAddress);
        console.log("result ", result.data);
      } catch(ex) {
        console.log(ex);
      }
    })
    .catch(function(err) {
      console.log(err);
    });
    
};