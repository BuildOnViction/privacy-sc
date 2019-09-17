pragma solidity 0.4.24;
pragma experimental ABIEncoderV2;

import {Secp256k1} from "./Secp256k1.sol";
import "./SafeMath.sol";

interface IRegistryInterface {
    function getPrivacyAddress(address _normal) external view returns (bytes);

    function getNormalAddress(bytes _privacy) external view returns (address);
}

contract PrivacyCT {
    using SafeMath for uint256;
    struct CompressPubKey {
        uint8 yBit;
        uint256 x;
    }

    uint256[] outputSum;
    uint256[] inputSum;
    uint i;
    uint outputLength;
    uint8 yBit;
    uint x;
    uint256[2] temp2;
    address RegistryContract = 0xbb32d285e4cF30d439F8106bbA926941730fbf1E;

    struct UTXO {
        CompressPubKey commitment;
        CompressPubKey pubkey;
        uint256 amount; //encoded amount
        CompressPubKey txPub;
    }

    event NewUTXO(uint256 _index,
        uint256 _commitmentX,
        uint8 _commitmentYBit,
        uint256 _pubkeyX,
        uint8 _pubkeyYBit,
        uint256 _amount,
        uint256 _txPubX,
        uint8 _txPubYBit);

    UTXO[] public utxos;
    mapping(uint256 => bool) public spentUTXOs;
    //mapping(uint256 => bool) public keyImages;

    //the first step for every one to use private transactions is deposit to the contract
    function deposit(uint _pubkeyX, uint _pubkeyY, uint _txPubKeyX, uint _txPubKeyY, uint256 _mask, uint256 _amount) external payable {
        uint[2] memory stealth;
        stealth[0] = _pubkeyX;
        stealth[1] = _pubkeyY;
        require(Secp256k1.onCurve(stealth));
        uint[2] memory txPub;
        txPub[0] = _txPubKeyX;
        txPub[1] = _txPubKeyY;
        require(Secp256k1.onCurve(txPub));
        (uint8 _ybitComitment, uint xCommitment) = Secp256k1.pedersenCommitment(_mask, msg.value);
        (uint8 pybit, uint px) = Secp256k1.compress(stealth);
        (uint8 txybit, uint txx) = Secp256k1.compress(txPub);
        utxos.push(UTXO ({
            commitment: CompressPubKey(_ybitComitment + 2, xCommitment),
            pubkey: CompressPubKey(pybit + 2, px),
            amount: _amount,
            txPub: CompressPubKey(txybit + 2, txx)})
        );
        UTXO storage lastUTXO = utxos[utxos.length.sub(1)];
        emit NewUTXO(utxos.length.sub(1), lastUTXO.commitment.x, lastUTXO.commitment.yBit,
            lastUTXO.pubkey.x, lastUTXO.pubkey.yBit, lastUTXO.amount,
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
    function privateSend(uint256[] memory _inputIDs,
        uint256[][2] memory _outputs, //1/3 for commitments, 1/3 for stealths,, 1/3 for txpubs
        uint256[] memory _amounts) public {
        //call precombiled to verify proof
        require(_inputIDs.length < 10, "too many inputs");
        require(_inputIDs.length > 0, "no inputs");
        require(_outputs.length % 3 == 0);
        for(i = 0; i < _inputIDs.length; i++) {
            require(!spentUTXOs[_inputIDs[i]], "input already spent");
        }

        require(_amounts.length == _outputs.length.div(3));

        //compute sum of input
        inputSum = Secp256k1.decompress(utxos[_inputIDs[0]].commitment.yBit, utxos[_inputIDs[0]].commitment.x);
        for (i = 1; i < _inputIDs.length; i++) {
            uint256[2] memory point = Secp256k1.decompress(utxos[_inputIDs[i]].commitment.yBit, utxos[_inputIDs[i]].commitment.x);
            (uint256 _x, uint256 _y) = Secp256k1.add(inputSum[0], inputSum[1], point[0], point[1]);
            inputSum[0] = _x;
            inputSum[1] = _y;
        }

        //compute sum of outputs
        outputSum = _outputs[0];
        for (i = 1; i < _outputs.length.div(3); i++) {
            (_x, _y) = Secp256k1.add(outputSum[0], outputSum[1], _outputs[i][0], _outputs[i][1]);
            outputSum[0] = _x;
            outputSum[1] = _y;
        }
        require(inputSum[0] == outputSum[0] && inputSum[1] == outputSum[1]);
        //create output UTXOs
        outputLength = _outputs.length.div(3);
        for (i = 0; i < outputLength; i++) {
            (uint8 yBit, uint256 x) = Secp256k1.compressXY(_outputs[i][0], _outputs[i][1]);
            (uint8 yBitPub, uint256 xPub) = Secp256k1.compressXY(_outputs[outputLength.add(i)][0], _outputs[outputLength.add(i)][1]);
            (uint8 yBitTxPub, uint256 xTxPub) = Secp256k1.compressXY(_outputs[outputLength.mul(2).div(3).add(i)][0], _outputs[outputLength.mul(2).div(3).add(i)][1]);
            utxos.push(UTXO ({
                commitment: CompressPubKey(yBit, x),
                pubkey: CompressPubKey(yBitPub, xPub),
                amount: _amounts[i],
                txPub: CompressPubKey(yBitTxPub, xTxPub)})
            );
            emit NewUTXO(utxos.length - 1, x, yBit,
                xPub, yBitPub,
                _amounts[i],
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
    function withdrawFunds(uint _utxoIndex,
        uint256[] memory _amounts,
        bytes[] memory _rs, address recipient,
        uint256[] memory _commitmentAfter) public {
        //call precombiled to verify proof
        require(_rs.length == 2 && _rs[0].length == 32 && _rs[1].length == 32 && _utxoIndex < utxos.length && !spentUTXOs[_utxoIndex]);
        temp2[0] = bytesToUint(_rs[0]);
        temp2[1] = bytesToUint(_rs[1]);
        uint[2] memory pubkey = Secp256k1.decompress(utxos[_utxoIndex].pubkey.yBit - 2, utxos[_utxoIndex].pubkey.x);
        uint hash = uint(keccak256(utxos[_utxoIndex].commitment.yBit,
            utxos[_utxoIndex].commitment.x,
            utxos[_utxoIndex].pubkey.yBit,
            utxos[_utxoIndex].pubkey.x,
            recipient));
        require(Secp256k1.validateSignature(hash, temp2, pubkey), "signature is not valid");
        //send money to recipient
        require(recipient != address(0x0), "address not registered yet");
        recipient.transfer(_amounts[0]);

        spentUTXOs[_utxoIndex] = true;

        inputSum = Secp256k1.decompress(utxos[_utxoIndex].commitment.yBit - 2, utxos[_utxoIndex].commitment.x);
        (yBit, x) = Secp256k1.pedersenCommitment(0, _amounts[0]);
        outputSum = Secp256k1.decompress(yBit, x);
        (outputSum[0], outputSum[1]) = Secp256k1.add(outputSum[0], outputSum[1], _commitmentAfter[0], _commitmentAfter[1]);
        require(outputSum[0] == inputSum[0] && outputSum[1] == inputSum[1]);
        (yBit, x) = Secp256k1.compressXY(_commitmentAfter[0], _commitmentAfter[1]);
        utxos.push(UTXO({
            commitment: CompressPubKey(yBit, x),
            pubkey: CompressPubKey(utxos[_utxoIndex].pubkey.yBit, utxos[_utxoIndex].pubkey.x),
            amount: _amounts[1],
            txPub: CompressPubKey(utxos[_utxoIndex].txPub.yBit, utxos[_utxoIndex].txPub.x)}));
        emit NewUTXO(utxos.length - 1, x, yBit,
            utxos[_utxoIndex].pubkey.x, utxos[_utxoIndex].pubkey.yBit,
            _amounts[1],
            utxos[_utxoIndex].txPub.x, utxos[_utxoIndex].txPub.yBit);
    }

    function storeTxData(byte[] proof, bool parseOutput) private {
        uint8 rs = uint8(proof[0]);
        uint8 numInput = uint8(proof[1]);
        uint64 cursor = 2 + rs * numInput * 8;
        bytes memory ki = new bytes(33);
        for(uint8 i = 0; i < numInput; i++) {
            for(uint8 j = 0; j < 33; i++) {
                ki[j] = proof[cursor + i*33 + j];
            }
            //keyImages[uint256(keccak256(ki))] = true;
        }
        //Store UTXOs
        /*cursor += numInput * 33;
        uint8 numOut = uint8(proof[cursor++]);
        for(i = 0; i < numOut; i++) {
            UTXO memory utxo;
            for(j = 0; j < 33; i++) {
                utxo.commitment[j] = proof[cursor + i*130 + j];
            }

            for(j = 0; j < 33; i++) {
                utxo.pubkey[j] = proof[cursor + i*130 + 33 + j];
            }

            for(j = 0; j < 32; i++) {
                utxo.amount[j] = proof[cursor + i*130 + 33 + 33 + j];
            }

            for(j = 0; j < 32; i++) {
                utxo.mask[j] = proof[cursor + i*130 + 33 + 33 + 32 + j];
            }
            utxos.push(utxo);
        }*/
    }

    function verifyProof(byte[] memory proof) private returns (bool) {
        return true;
    }

    function verifyWithdrawal(byte[] memory proof, uint256 _amount) private returns (bool) {
        return true;
    }

    function getUTXO(uint256 index) public view returns (uint256 ,
        uint8 ,
        uint256 ,
        uint8 ,
        uint256 ,
        uint256 ,
        uint8 ) {
        return (utxos[index].commitment.x, utxos[index].commitment.yBit, utxos[index].pubkey.x, utxos[index].pubkey.yBit, utxos[index].amount, utxos[index].txPub.x, utxos[index].txPub.yBit);
    }

    //dont receive any money via default callback
    function () external payable {
        revert();
    }

    function bytesToUint(bytes b) public returns (uint256){
        uint256 number;
        for(uint i=0;i<b.length;i++){
            number = number + uint(b[i])*(2**(8*(b.length-(i+1))));
        }
        return number;
    }
}
