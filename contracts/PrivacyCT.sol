pragma solidity ^0.5.0;
import {Secp256k1} from "./Secp256k1.sol";
import "./SafeMath.sol";
import "../../maxbet2/maxbet/src/contracts/full.sol";

contract PrivacyCT {
    using SafeMath for uint256;
    struct CompressPubKey {
        uint8 yBit;
        uint256 x;
    }

    struct UTXO {
        CompressPubKey commitment;
        CompressPubKey pubkey;
        uint256 amount; //encoded amount
        uint256 mask;   //encoded blinding factor
        CompressPubKey txPub;
    }

    event NewUTXO(uint256 _commitmentX,
                    uint8 _commitmentYBit,
                    uint256 _pubkeyX,
                    uint8 _pubkeyYBit,
                    uint256 _amount,
                    uint256 _mask,
                    uint256 _txPubX,
                    uint8 _txPubYBit);

    UTXO[] utxos;
    mapping(uint256 => bool) public spentUTXOs;
    //mapping(uint256 => bool) public keyImages;

    //the first step for every one to use private transactions is deposit to the contract
    function deposit(uint256[2] calldata _commitment, uint256[2] calldata _pubkey) external payable {
        (uint8 yBit, uint256 x) = Secp256k1.compress(_commitment);
        (uint8 yBitPub, uint256 xPub) = Secp256k1.compress(_pubkey);
        utxos.push(UTXO (
            commitment: CompressPubKey(yBit, x),
            pubkey: CompressPubKey(yBitPub, xPub),
            amount: msg.value,
            mask: uint256(0),
            txPub: CompressPubKey(0, 0))
        );
        UTXO storage lastUTXO = utxos[utxos.length.sub(1)];
        emit NewUTXO(lastUTXO.commitment.x, lastUTXO.commitment.yBit,
                    lastUTXO.pubkey.x, lastUTXO.pubkey.yBit,
                    lastUTXO.amount, lastUTXO.mask,
                    lastUTXO.txPub.x, lastUTXO.txPub.yBit);
    }
    //function privateSend only contain the proof
    //The proof contains pretty much stuffs
    //Ring size rs: 1 byte => proof[0]
    //num input: number of real inputs: 1 byte => proof[1]
    //List of inputs/UTXO index typed uint64 => total size = rs * numInput * 8 = proof[0]*proof[1]*8
    //List of key images: total size = numInput * 33 = proof[1] * 33
    //number of output n: 1 byte
    //List of output => n * 130 bytes
    //transaction fee: uint256 => 32 byte
    //ringCT proof size ctSize: uint16 => 2 byte
    //ringCT proof: ctSize bytes
    //bulletproofs: bp
    function privateSend(uint256[] calldata _inputIDs,
                        uint256[][2] calldata _commitments,
                        uint256[][2] calldata _pubkeys,
                        uint256[] calldata _amounts,
                        uint256[] calldata _masks,
                        uint256[][2] calldata _txPubs) external {
        //call precombiled to verify proof
        require(_inputIDs.length < utxos.length, "too many inputs");
        require(_inputIDs.length > 0, "no inputs");
        for(uint256 i = 0; i < _inputIDs.length; i++) {
            require(!spentUTXOs[_inputIDs[i]], "input already spent");
        }

        require(_commitments.length > 0 &&
                _commitments.length == _pubkeys.length &&
                _commitments.length == _amounts.length &&
                _commitments.length == _masks.length &&
                _commitments.length == _txPubs.length);

        //compute sum of input
        uint256[2] memory inputSum = Secp256k1.decompress(utxos[_inputIDs[0]].commitment.yBit, utxos[_inputIDs[0]].commitment.x);
        for (uint256 i = 1; i < _inputIDs.length; i++) {
            uint256[2] memory point = Secp256k1.decompress(utxos[_inputIDs[i]].commitment.yBit, utxos[_inputIDs[i]].commitment.x);
            (uint256 _x, uint256 _y) = Secp256k1.add(inputSum[0], inputSum[1], point[0], point[1]);
            inputSum[0] = _x;
            inputSum[1] = _y;
        }

        //compute sum of outputs
        uint256[2] memory outputSum = _commitments[0];
        for (uint256 i = 1; i < _commitments.length; i++) {
            (uint256 _x, uint256 _y) = Secp256k1.add(outputSum[0], outputSum[1], _commitments[i][0], _commitments[i][1]);
            outputSum[0] = _x;
            outputSum[1] = _y;
        }
        require(inputSum[0] == outputSum[0] && inputSum[1] == outputSum[1]);
        //create output UTXOs
        for (uint256 i = 0; i < _commitments.length; i++) {
            (uint8 yBit, uint256 x) = Secp256k1.compress(_commitments[i]);
            (uint8 yBitPub, uint256 xPub) = Secp256k1.compress(_pubkeys[i]);
            (uint8 yBitTxPub, uint256 xTxPub) = Secp256k1.compress(_txPubs[i]);
            utxos.push(UTXO (
                commitment: CompressPubKey(yBit, x),
                pubkey: CompressPubKey(yBitPub, xPub),
                amount: _amounts[i],
                mask: _masks[i],
                txPub: CompressPubKey(yBitTxPub, xTxPub))
            );
            emit NewUTXO(x, yBit,
                        xPub, yBitPub,
                        _amounts[i], _masks[i],
                        xTxPub, yBitTxPub);
        }
    }

    //function withdrawFunds only contain the proof and the desired amount
    //The proof contains pretty much stuffs
    //Ring size rs: 1 byte => proof[0]
    //num input: number of real inputs: 1 byte => proof[1]
    //List of inputs/UTXO index typed uint64 => total size = rs * numInput * 8 = proof[0]*proof[1]*8
    //List of key images: total size = numInput * 33 = proof[1] * 33
    //number of output n: 1 byte
    //List of output => n * 130 bytes
    //transaction fee: uint256 => 32 byte
    //ringCT proof size ctSize: uint16 => 2 byte
    //ringCT proof: ctSize bytes
    //ringCT is created between the inputs and a virtual output (that has commitment to zero) that sends funds to the recipient
    //since the funds in the output is exposed, no bp rangeproof is needed
    function withdrawFunds(address payable recipient, uint256 _amount, byte[] calldata proof) external {
        //call precombiled to verify proof
        require(verifyWithdrawal(proof, _amount));

        //send money to recipient
        recipient.transfer(_amount);

        //store keyImages and UTXO similar to privateSend
        storeTxData(proof, false);
    }

    function storeTxData(byte[] memory proof, bool parseOutput) private {
        uint8 rs = uint8(proof[0]);
        uint8 numInput = uint8(proof[1]);
        uint64 cursor = 2 + rs * numInput * 8;
        bytes memory ki = new bytes(33);
        for(uint8 i = 0; i < numInput; i++) {
            for(uint8 j = 0; j < 33; i++) {
                ki[j] = proof[cursor + i*33 + j];
            }
            keyImages[uint256(keccak256(ki))] = true;
        }
        //Store UTXOs
        cursor += numInput * 33;
        uint8 numOut = uint8(proof[cursor++]);
        for(uint8 i = 0; i < numOut; i++) {
            UTXO memory utxo;
            for(uint8 j = 0; j < 33; i++) {
                utxo.commitment[j] = proof[cursor + i*130 + j];
            }

            for(uint8 j = 0; j < 33; i++) {
                utxo.pubkey[j] = proof[cursor + i*130 + 33 + j];
            }

            for(uint8 j = 0; j < 32; i++) {
                utxo.amount[j] = proof[cursor + i*130 + 33 + 33 + j];
            }

            for(uint8 j = 0; j < 32; i++) {
                utxo.mask[j] = proof[cursor + i*130 + 33 + 33 + 32 + j];
            }
            utxos.push(utxo);
        }
    }

    function verifyProof(byte[] memory proof) private returns (bool) {
        return true;
    }

    function verifyWithdrawal(byte[] memory proof, uint256 _amount) private returns (bool) {
        return true;
    }

    function getUTXO(uint256 index) public view returns (byte[33] memory, byte[33] memory, bytes32 amount, bytes32 blind) {
        return (utxos[index].commitment, utxos[index].pubkey, utxos[index].amount[0], utxos[index].amount[1]);
    }

    //dont receive any money via default callback
    function () external payable {
        revert();
    }
}
