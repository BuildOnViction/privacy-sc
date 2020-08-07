pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;
import "./PTRC21.sol";

contract TomoP is Privacy {
    
    constructor (address token,
        uint256 minFee,
        uint256 depositFee,
        uint256 withdrawFee
    )  PTRC21(token, minFee, depositFee, withdrawFee) public {}
    
    function deposit(uint _pubkeyX,
        uint _pubkeyY,
        uint _txPubKeyX,
        uint _txPubKeyY,
        uint256 _mask,
        uint256 _amount,
        uint256 _encodedMask,
        byte[137] memory _data) public payable {
            // convert deposit value to right decimals
            uint256 _value = _toPrivacyValue(msg.value);
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
        issuer().transfer(
            _externalValue
        );
        emit TransactionFee(issuer(), _externalValue);
    }

    function doTransferOut(address payable to, uint256 amount) internal {
        /* Send the Ether, with minimal gas and revert on failure */
        to.transfer(amount);
    }
}