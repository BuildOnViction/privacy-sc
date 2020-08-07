pragma solidity ^0.5.0;

contract BulletProofVerifier {
    address BP_PRECOMPILED = 0x0000000000000000000000000000000000000028;
    function VerifyRangeProof(bytes memory data) public returns (bool) {
        (bool success,) = BP_PRECOMPILED.call(data);
        return success;
    }

    function CheckRangeProof(bytes memory data) public returns (bool) {
        (bool success,) = BP_PRECOMPILED.call(data);
        require(success);
        return success;
    }
}
