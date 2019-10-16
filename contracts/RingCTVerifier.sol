pragma solidity 0.5.0;

contract RingCTVerifier {
    address RINGCT_PRECOMPILED = 0x000000000000000000000000000000000000001e;
    function VerifyRingCT(bytes memory data) public returns (bool) {
        (bool success,) = RINGCT_PRECOMPILED.call(data);
        return success;
    }

    function ComputeSignatureSize(uint256 numRing, uint256 ringSize) public returns (uint256) {
        return 8 + 8 + 32 + 32 + numRing*ringSize*32 + numRing*ringSize*33 + numRing*33;
    }
}