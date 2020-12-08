pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;
import "./pTRC21.sol";

contract pTomo is Privacy {
    bool public isActivated = false;
    address[] public earlyDepositers;
    uint public MIN_EARLY_DEPOSIT;
    uint public MAX_EARLY_DEPOSITER;
    event Activated();
    event NewDeposit(address depositer, uint256 amount);
    
    modifier onlyActivated() {
        require(isActivated == true);
        _;
    }
    
    constructor (address token,
        string memory name,
        uint256 sendingFee,
        uint256 depositFee,
        uint256 withdrawFee,
        uint256 minEarlyDeposit,
        uint256 maxEarlyDepositer
    )  pTRC21(token, name, sendingFee, depositFee, withdrawFee) public {
        MIN_EARLY_DEPOSIT = minEarlyDeposit;
        MAX_EARLY_DEPOSITER = maxEarlyDepositer;
    }
    
    function deposit(
        uint256 value, // uniform interface with deposit token
        uint _pubkeyX,
        uint _pubkeyY,
        uint _txPubKeyX,
        uint _txPubKeyY,
        uint256 _mask,
        uint256 _amount,
        uint256 _encodedMask,
        byte[137] memory _data) public payable {
            // convert deposit value to right decimals
            uint256 _value = _toPrivacyValue(msg.value);
            require(_value > getDepositFee(), "deposit amount must be greater than deposit fee");
            
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
            
            if (isActivated == false && msg.value >= MIN_EARLY_DEPOSIT) {
                _addDepositer(msg.sender, msg.value);
            }
    }
    
    function _addDepositer(address depositer, uint256 value) internal {
        // check duplicated address
        bool isMarked = false;
        for(uint i = 0; i < earlyDepositers.length; i++) {
            if (earlyDepositers[i] == depositer) {
                isMarked = true;
                break;
            }
        }
        
        if (isMarked) {
            return;
        }
        
        earlyDepositers.length = earlyDepositers.length + 1;
        earlyDepositers[earlyDepositers.length - 1] = depositer;
        emit NewDeposit(depositer, value);
        
        if (earlyDepositers.length == MAX_EARLY_DEPOSITER) {
            isActivated = true;
            emit Activated();
        }
    }
    
    function privateSend(uint256[] memory _inputIDs,
        uint256[] memory _outputs, //1/3 for commitments, 1/3 for stealths,, 1/3 for txpubs
        uint256[] memory _amounts, //1/2 for encryptd amounts, 1/2 for masks
        bytes memory _ringSignature,
        bytes memory _bp,
        byte[137] memory _data) public onlyActivated {
            super.privateSend(_inputIDs, _outputs, _amounts, _ringSignature, _bp, _data);
    }
    
    function withdrawFunds(uint[] memory _inputIDs, //multiple rings
        uint256[] memory _outputs, //1/3 for commitments, 1/3 for stealths,, 1/3 for txpubs : only contain 1 output
        uint256 _withdrawalAmount,
        uint256[2] memory _amounts, // _amounts[0]: encrypted amount, _amounts[1]: encrypted mask
        address payable _recipient,
        bytes memory _ringSignature,
        bytes memory _bp,
        byte[137] memory _data) public onlyActivated {
            super.withdrawFunds(_inputIDs, _outputs, _withdrawalAmount, _amounts, _recipient, _ringSignature, _bp, _data);
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