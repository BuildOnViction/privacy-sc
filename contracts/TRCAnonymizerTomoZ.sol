pragma solidity 0.5.0;
import "./SafeMath.sol";
import "./ITRC21.sol";

/**
 * @title Standard TRC21 token
 * @dev Implementation of the basic standard token.
 */
contract TRCAnonymizerTomoZBase is ITRC21 {
    using SafeMath for uint256;

    mapping (address => uint256) private _balances;
    uint256 private _minFee;
    address payable private _issuer;
    mapping (address => mapping (address => uint256)) private _allowed;
    uint256 private _totalSupply;

    /**
     * @dev Total number of tokens in existence
     */
    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev  The amount fee that will be lost when transferring.
     */
    function minFee() public view returns (uint256) {
        return _minFee;
    }

    /**
     * @dev token's foundation
     */
    function issuer() public view returns (address payable) {
        return _issuer;
    }

    function balanceOf(address owner) public view returns (uint256) {
        return _balances[owner];
    }

    function estimateFee(uint256 value) public view returns (uint256) {
        return value.mul(0).add(_minFee);
    }

    function allowance(address owner,address spender) public view returns (uint256){
        //do nothing
        return 0;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        //do nothing
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        //do nothing
        return true;
    }

    function transferFrom(address from,	address to,	uint256 value)	public returns (bool) {
        //do nothing
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        //do nothing
    }

    function _mint(address account, uint256 value) internal {
        //do nothing
    }

    /**
     * @dev Transfers token's foundation to new issuer
     * @param newIssuer The address to transfer ownership to.
     */
    function _changeIssuer(address payable newIssuer) internal {
        require(newIssuer != address(0));
        _issuer = newIssuer;
    }

    /**
     * @dev Change minFee
     * @param value minFee
     */
    function _changeMinFee(uint256 value) internal {
        _minFee = value;
    }

}

contract TRCAnonymizerTomoZInitializer is TRCAnonymizerTomoZBase {
    string private _name;
    string private _symbol;
    uint8 private _decimals;

    constructor (string memory name, string memory symbol, uint8 decimals, uint256 cap, uint256 minFee) public {
        _name = name;
        _symbol = symbol;
        _decimals = decimals;
        _mint(msg.sender, cap);
        _changeIssuer(msg.sender);
        _changeMinFee(minFee);
    }

    /**
     * @return the name of the token.
     */
    function name() public view returns (string memory) {
        return _name;
    }

    /**
     * @return the symbol of the token.
     */
    function symbol() public view returns (string memory) {
        return _symbol;
    }

    /**
     * @return the number of decimals of the token.
     */
    function decimals() public view returns (uint8) {
        return _decimals;
    }

    function setMinFee(uint256 value) public {
        require(msg.sender == issuer());
        _changeMinFee(value);
    }
}

contract TRCAnonymizerTomoZ is TRCAnonymizerTomoZInitializer {
    constructor () TRCAnonymizerTomoZInitializer("TomoAnonymizer", "TAZ", 18, 1000000000* (10**18), 0) public {}
}