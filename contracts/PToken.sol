pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;
import "./PTRC21.sol";

contract PToken is Privacy {
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
        _token.transfer(issuer(), _externalValue);

        bool success;
        assembly {
            switch returndatasize()
                case 0 {                       // This is a non-standard ERC-20
                    success := not(0)          // set success to true
                }
                case 32 {                      // This is a compliant ERC-20
                    returndatacopy(0, 0, 32)
                    success := mload(0)        // Set `success = returndata` of external call
                }
                default {                      // This is an excessively non-compliant ERC-20, revert.
                    revert(0, 0)
                }
        }
        require(success, "TOKEN_TRANSFER_FEE_FAILED");
        emit TransactionFee(issuer(), _externalValue);
    }
    
    function doTransferIn(address from, uint amount) internal returns (uint) {
        ITRC21 _token = ITRC21(token());
        uint balanceBefore = _token.balanceOf(address(this));
        _token.transferFrom(from, address(this), amount);

        bool success;
        assembly {
            switch returndatasize()
                case 0 {
                       // This is a non-standard ERC-20
                    success := not(0)          // set success to true
                }
                case 32 {                      // This is a compliant ERC-20
                    returndatacopy(0, 0, 32)
                    success := mload(0)        // Set `success = returndata` of external call
                }
                default {                      // This is an excessively non-compliant ERC-20, revert.
                    revert(0, 0)
                }
        }
        require(success, "TOKEN_TRANSFER_IN_FAILED");

        // Calculate the amount that was *actually* transferred
        uint balanceAfter = _token.balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "TOKEN_TRANSFER_IN_OVERFLOW");
        return balanceAfter - balanceBefore;   // underflow already checked above, just subtract
    }

    function doTransferOut(address payable to, uint256 amount) internal {
        ITRC21 _token = ITRC21(token());
        _token.transfer(to, amount);

        bool success;
        assembly {
            switch returndatasize()
                case 0 {                      // This is a non-standard ERC-20
                    success := not(0)          // set success to true
                }
                case 32 {                     // This is a complaint ERC-20
                    returndatacopy(0, 0, 32)
                    success := mload(0)        // Set `success = returndata` of external call
                }
                default {                     // This is an excessively non-compliant ERC-20, revert.
                    revert(0, 0)
                }
        }
        require(success, "TOKEN_TRANSFER_OUT_FAILED");
    }
}