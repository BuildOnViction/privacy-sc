pragma solidity ^0.5.0;

library RingCTVerifier {
    address constant RINGCT_PRECOMPILED = 0x000000000000000000000000000000000000001e;
    address constant RINGCT_PRECOMPILED_MESSAGE = 0x000000000000000000000000000000000000001F;
    function VerifyRingCT(bytes memory data) internal returns (bool) {
        (bool success,) = RINGCT_PRECOMPILED.call(data);
        return success;
    }

    function VerifyRingCTWithMessage(bytes memory data) internal returns (bool) {
        (bool success,) = RINGCT_PRECOMPILED_MESSAGE.call(data);
        return success;
    }
    function ComputeSignatureSize(uint256 numRing, uint256 ringSize) internal pure returns (uint256) {
        return 8 + 8 + 32 + 32 + numRing*ringSize*32 + numRing*ringSize*33 + numRing*33;
    }
}
