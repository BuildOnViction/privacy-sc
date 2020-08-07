pragma solidity ^0.5.0;
import "./SafeMath.sol";

library UnitUtils {
    using SafeMath for uint256;
    function Wei2Gwei(uint256 _amount) internal view returns (uint256) {
        return _amount.div(10**9);
    }

    function Gwei2Wei(uint256 _amount) internal view returns (uint256) {
        return _amount.mul(10**9);
    }
}