pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;
import "./pTRC21.sol";

contract pToken is Privacy {
    constructor (address token,
        uint256 minFee,
        uint256 depositFee,
        uint256 withdrawFee
    )  PTRC21(token, minFee, depositFee, withdrawFee) public {}
    
    function deposit(
        uint256 value,
        uint _pubkeyX,
        uint _pubkeyY,
        uint _txPubKeyX,
        uint _txPubKeyY,
        uint256 _mask,
        uint256 _amount,
        uint256 _encodedMask,
        byte[137] memory _data) public  {
            uint actualAddAmount = doTransferIn(msg.sender, value);
            
            uint256 _value = _toPrivacyValue(actualAddAmount);
            require(_value > getDepositFee(), "deposit amount must be strictly greater than deposit fee");
            
            _deposit(
                _value,
                _pubkeyX,
                _pubkeyY,
                _txPubKeyX,
                _txPubKeyY,
                _mask,
                _amount,
                _encodedMask,
                _data);
    }

function transferFee(uint256 fee) internal {
        uint256 _externalValue = _toExternalValue(fee);
        ITRC21 _token = ITRC21(token());
        uint256 tokenFee = _token.estimateFee(_externalValue)
        require(_externalValue >= tokenFee, "WITHDRAW_VALUE_MUST_BE_GREATER_THAN_TOKEN_FEE");
        _token.transfer(issuer(), _externalValue - tokenFee);
        emit TransactionFee(issuer(), _externalValue - tokenFee);
    }
    
    function doTransferIn(address from, uint amount) internal returns (uint) {
        ITRC21 _token = ITRC21(token());
        uint balanceBefore = _token.balanceOf(address(this));
        _token.transferFrom(from, address(this), amount);

        uint balanceAfter = _token.balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "TOKEN_TRANSFER_IN_OVERFLOW");
        return balanceAfter - balanceBefore; 
    }

    function doTransferOut(address payable to, uint256 amount) internal {
        ITRC21 _token = ITRC21(token());
        _token.transfer(to, amount);
    }
}