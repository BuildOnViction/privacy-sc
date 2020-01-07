pragma solidity 0.5.0;
import "./SafeMath.sol";

library UnitUtils {
    using SafeMath for uint256;
    function Wei2Gwei(uint256 _amount) internal view returns (uint256) {
        return _amount.div(10**9);
    }

    function Gwei2Wei(uint256 _amount) internal view returns (uint256) {
        return _amount.mul(10**9);
    }

    function decimalConvert(uint256 _amount, uint8 _from, uint8 _to) internal view returns (uint256) {
        if (_from == _to) return _amount;
        if (_from > _to) return _amount.div(uint256(10)**(_from - _to));
        return _amount.mul(uint256(10)**(_to - _from));
    }
}