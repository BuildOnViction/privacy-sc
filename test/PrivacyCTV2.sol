pragma solidity 0.4.24;

import "truffle/Assert.sol";
import "truffle/DeployedAddresses.sol";
import "../contracts/PrivacyCTV2.sol";

contract TestPrivacyCTV2 {
  function testGetUTXOs() {
    PrivacyCTV2 privacy = new PrivacyCTV2();

    privacy.deposit(
        
    )

    Assert.equal(privacy.getBalance(tx.origin), expected, "Owner should have 10000 PrivacyCTV2 initially");
  }

}