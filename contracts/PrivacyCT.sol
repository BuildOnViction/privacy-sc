pragma solidity 0.5.0;
pragma experimental ABIEncoderV2;
import {Secp256k1} from "./Secp256k1.sol";
import "./SafeMath.sol";
import "./RingCTVerifier.sol";
import "./CopyUtils.sol";
import "./TRC21.sol";

interface IRegistryInterface {
    function getPrivacyAddress(address _normal) external view returns (bytes memory);
    function getNormalAddress(bytes calldata _privacy) external view returns (address);
}
contract PrivacyCT is PrivacyTRC21TOMO, RingCTVerifier {
    using SafeMath for uint256;
    struct CompressPubKey {
        uint8 yBit;
        uint256 x;
    }
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
        uint256 mask;   //encoded mask
    }

    struct Transaction {
        uint[] utxos;   //indexes of utxos created by the transaction
    }

    UTXO[] public utxos;
    Transaction[] txs;

    mapping(uint256 => bool) keyImagesMapping;


    //--------------------------EVENTS---------------------------------
    event NewUTXO(uint256[3] _Xs,   //commitmentX, pubkeyX, txPubX
        uint8[3] _YBits,        //commitmentYBit, pubkeyYBit, _txPubYBit
        uint256[2] _amount,
        uint256 _index);

    event NewTransaction(uint256 _time, uint256[] _utxoIndexs);

    event InputSum(uint256 _in1, uint256 _in2);
    event OutputSum(uint256 _out1, uint256 _out2);
    event CompressXYInput(uint256 _in1, uint256 _in2, uint8 yBit);
    event CommitmentInput(uint8 _yBit, uint256 _X);
    event HashSign(bytes32 _hash);
    event RingParams(uint256 _numRing, uint256 _ringSize, uint256 _inputLength, uint256 _actualRingProofSize);
    event Message(bytes _raw, uint256 _length);

    /**the first step for every one to use private transactions is deposit to the contract
    *@param {_pubkeyX
    */
    function deposit(uint _pubkeyX,
        uint _pubkeyY,
        uint _txPubKeyX,
        uint _txPubKeyY,
        uint256 _mask,
        uint256 _amount,
        uint256 _encodedMask) external payable {
        uint[2] memory stealth;
        stealth[0] = _pubkeyX;
        stealth[1] = _pubkeyY;
        require(Secp256k1.onCurveXY(_pubkeyX, _pubkeyY));
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
            txPub: CompressPubKey(txybit + 2, txx),
            mask: _encodedMask})
        );
        UTXO storage lastUTXO = utxos[utxos.length.sub(1)];
        emit NewUTXO([lastUTXO.commitment.x, lastUTXO.pubkey.x, lastUTXO.txPub.x],
            [lastUTXO.commitment.yBit, lastUTXO.pubkey.yBit, lastUTXO.txPub.yBit],
            [lastUTXO.amount, lastUTXO.mask],
            utxos.length.sub(1));

        /*Transaction memory tx;
        txs.push(tx);
        txs[txs.length.sub(1)].utxos.push(utxos.length.sub(1));
        emit NewTransaction(now, txs[txs.length.sub(1)].utxos);*/
    }
    event Inputs(uint256[] _inputIDs);
    event ParseBytes(uint256 _input, uint256 _checked, byte[33] raw);
    /**Send TOMO/Token privately
    *@param {_inputIDs} The index IDs of all decoys in all input rings, data is structured as [ring00,ring01,ring02,ring11...]
    *@param {_outputs} commitments, stealth addresses and transaction pubkeys of outputs produced by this private send
    *@param {_amounts} enrypted/encoded format of transaction outputs amounts and masks/blinding factors
    *@param {_ringSignature} ring signature that will be verified by precompiled contract
    */
    function privateSend(uint256[] memory _inputIDs,
        uint256[] memory _outputs, //1/3 for commitments, 1/3 for stealths,, 1/3 for txpubs
        uint256[] memory _amounts, //1/2 for encryptd amounts, 1/2 for masks
        bytes memory _ringSignature) public {

        require(_inputIDs.length < 100, "too many inputs");
        require(_inputIDs.length > 0, "no inputs");
        require(_outputs.length % 6 == 0 && _outputs.length <= 2*6);
        require(_amounts.length.div(2) == _outputs.length.div(6));

        //verify signature size
        require(_ringSignature.length > 16);
        //[0]: numRing
        //[1]: ringSize
        //[2]: public offset
        //[3]: key images offset
        uint256[4] memory ringParams;
        uint256[3] memory loopVars;
        ringParams[0] = convertBytesToUint(_ringSignature, 0, 8);    //numRing
        ringParams[1] = convertBytesToUint(_ringSignature, 8, 8);    //ringSize
        require(_inputIDs.length % (ringParams[1]) == 0);
        require(ComputeSignatureSize(ringParams[0], ringParams[1]) == _ringSignature.length);

        ringParams[2] = 80 + ringParams[0] * ringParams[1] *32;
        ringParams[3] = ringParams[2] + ringParams[0] * ringParams[1] * 33;

        //verify public keys is correct, the number of pubkey inputs = ringParams[0] * ringParams[1]
        //pubkeys start from offset: 80 + ringParams[0] * ringParams[1] *32
        //this look does not verify additional ring -  the last ring
        for(loopVars[0] = 0; loopVars[0] < ringParams[0] - 1; loopVars[0]++) {
            for(loopVars[1] = 0; loopVars[1] < ringParams[1]; loopVars[1]++) {
                (bool copied, byte[33] memory pk) = CopyUtils.Copy33Bytes(_ringSignature, ringParams[2] + (loopVars[0]*ringParams[1] + loopVars[1])*33);
                require(copied);
                require(uint8(pk[0]) % 2 ==
                    utxos[_inputIDs[loopVars[0]*(ringParams[1]) + loopVars[1]]].pubkey.yBit % 2);    //yBit same
                //emit ParseBytes(utxos[_inputIDs[loopVars[0]*(ringParams[1]) + loopVars[1]]].pubkey.x, convertBytes33ToUint(pk,  1, 32), pk);
                require(convertBytes33ToUint(pk,  1, 32) ==
                    utxos[_inputIDs[loopVars[0]*(ringParams[1]) + loopVars[1]]].pubkey.x);
            }
        }


        //verify additional ring
        //compute sum of outputs
        uint256[2] memory outSum;
        outSum[0] = _outputs[0];
        outSum[1] = _outputs[1];
        for (i = 1; i < _outputs.length.div(6); i++) {
            (outSum[0], outSum[1]) = Secp256k1.add(outSum[0], outSum[1], _outputs[i*2], _outputs[i*2+1]);
        }

        for(loopVars[1] = 0; loopVars[1] < ringParams[1]; loopVars[1]++) {
            uint256[2] memory point = [uint256(0),uint256(0)];
            //compute sum of: all input pubkeys + all input commitments
            for(loopVars[0] = 0; loopVars[0] < ringParams[0] - 1; loopVars[0]++) {
                if (point[0] == uint256(0)) {
                    (point[0], point[1]) = Secp256k1.decompressXY(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.x);
                    uint256[2] memory commitment = Secp256k1.decompress(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.x);
                    (point[0], point[1]) = Secp256k1.add(point[0], point[1], commitment[0], commitment[1]);
                } else {
                    uint256[2] memory temp = Secp256k1.decompress(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.x);
                    (point[0], point[1]) = Secp256k1.add(point[0], point[1], temp[0], temp[1]);
                    temp = Secp256k1.decompress(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.x);
                    (point[0], point[1]) = Secp256k1.add(point[0], point[1], temp[0], temp[1]);
                }
            }
            //sum - all output commitments
            (point[0], point[1]) = Secp256k1.sub(point[0], point[1], outSum[0], outSum[1]);
            (bool copied, byte[33] memory pk) = CopyUtils.Copy33Bytes(_ringSignature, ringParams[2] + ((ringParams[0] - 1)*ringParams[1] + loopVars[1])*33);
            require(copied);
            (uint8 ybit, uint256 compressX) = Secp256k1.compressXY(point[0], point[1]);
            //verify sum = the corresponding element in the last/additional ring
            //require(uint8(pk[0]) % 2 == yBit % 2);    //yBit same
            //require(convertBytes33ToUint(pk,  1, 32) == compressX);
        }
        (bool success, byte[] memory inputData) = CopyUtils.CopyBytes(_ringSignature, ringParams[2], ringParams[0]*ringParams[1]*33);
        require(success);
        bytes32 message;
        if (_outputs.length == 6) {
            bytes memory mes = abi.encodePacked(inputData, bytes32(_outputs[2]), bytes32(_outputs[3]));
            message = keccak256(mes);
            //emit Message(mes, mes.length);
        } else {
            bytes memory mes = abi.encodePacked(inputData, bytes32(_outputs[2]), bytes32(_outputs[3]), bytes32(_outputs[8]), bytes32(_outputs[9]));

            message = keccak256(mes);
            //emit Message(mes, mes.length);
        }
        //require(CopyUtils.CompareBytes(message, ringSignature, 16), "message must be equal");

        //verify key image spend
        for(loopVars[0] = 0; loopVars[0] < ringParams[0]; loopVars[0]++) {
            (bool success, byte[33] memory ki) = CopyUtils.Copy33Bytes(_ringSignature, ringParams[3] + loopVars[0]*33);
            require(success);
            uint256 kiHash = bytesToUint(keccak256(abi.encodePacked(ki)));
            require(!keyImagesMapping[kiHash], "key image is spent!");
            keyImagesMapping[kiHash] = true;
        }

        //verify ringSignature
        require(VerifyRingCT(_ringSignature), "signature failed");

        //create output UTXOs
        outputLength = _outputs.length.div(6);
        for (i = 0; i < outputLength; i++) {
            uint256[3] memory X;
            uint8[3] memory yBit;
            (yBit[0], X[0]) = Secp256k1.compressXY(_outputs[i*2], _outputs[i*2 + 1]);

            (yBit[1], X[1]) = Secp256k1.compressXY(_outputs[outputLength*2 + i*2], _outputs[outputLength*2 + i*2 + 1]);

            (yBit[2], X[2]) = Secp256k1.compressXY(_outputs[outputLength*4 + i*2], _outputs[outputLength*4 + i*2 + 1]);

            utxos.push(UTXO ({
                commitment: CompressPubKey(yBit[0] + 2, X[0]),
                pubkey: CompressPubKey(yBit[1] + 2, X[1]),
                amount: _amounts[i],
                txPub: CompressPubKey(yBit[2] + 2, X[2]),
                mask: _amounts[outputLength + i]
                })
            );
            emit NewUTXO([utxos[utxos.length - 1].commitment.x, utxos[utxos.length - 1].pubkey.x, utxos[utxos.length - 1].txPub.x],
                [utxos[utxos.length - 1].commitment.yBit, utxos[utxos.length - 1].pubkey.yBit, utxos[utxos.length - 1].txPub.yBit],
                [utxos[utxos.length - 1].amount, utxos[utxos.length - 1].mask],
                utxos.length - 1);
        }
    }

    /**Withdraw TOMO/Token privately without revealing which output is being spent
    *@param {_inputIDs} The index IDs of all decoys in all input rings, data is structured as [ring00,ring01,ring02,ring11...]
    *@param {_outputs} commitments, stealth addresses and transaction pubkeys of outputs produced by this private send
    *@param {_withdrawalAmount} the amount to be withdrawn
    *@param {_amounts} enrypted/encoded format of transaction outputs amounts and masks/blinding factors
    *@param {_recipient} the recipient of the withdrawing transaction
    *@param {_ringSignature} ring signature that will be verified by precompiled contract
    */
    function withdrawFunds(uint[] memory _inputIDs, //multiple rings
        uint256[] memory _outputs, //1/3 for commitments, 1/3 for stealths,, 1/3 for txpubs : only contain 1 output
        uint256 _withdrawalAmount,
        uint256[2] memory _amounts, // _amounts[0]: encrypted amount, _amounts[1]: encrypted mask
        address payable _recipient,
        bytes memory _ringSignature) public {

        require(_inputIDs.length < 100, "too many inputs");
        require(_inputIDs.length > 0, "no inputs");
        require(_outputs.length % 6 == 0 && _outputs.length <= 2*6);
        require(1 == _outputs.length.div(6));

        //verify signature size
        require(_ringSignature.length > 16);
        //[0]: numRing
        //[1]: ringSize
        //[2]: public offset
        //[3]: key images offset
        uint256[4] memory ringParams;
        uint256[3] memory loopVars;
        ringParams[0] = convertBytesToUint(_ringSignature, 0, 8);    //numRing
        ringParams[1] = convertBytesToUint(_ringSignature, 8, 8);    //ringSize
        require(_inputIDs.length % (ringParams[1]) == 0);
        require(ComputeSignatureSize(ringParams[0], ringParams[1]) == _ringSignature.length);

        ringParams[2] = 80 + ringParams[0] * ringParams[1] *32;
        ringParams[3] = ringParams[2] + ringParams[0] * ringParams[1] * 33;

        //verify public keys is correct, the number of pubkey inputs = ringParams[0] * ringParams[1]
        //pubkeys start from offset: 80 + ringParams[0] * ringParams[1] *32
        //this does not verify additional ring (the last ring)
        for(loopVars[0] = 0; loopVars[0] < ringParams[0] - 1; loopVars[0]++) {
            for(loopVars[1] = 0; loopVars[1] < ringParams[1]; loopVars[1]++) {
                (bool copied, byte[33] memory pk) = CopyUtils.Copy33Bytes(_ringSignature, ringParams[2] + (loopVars[0]*ringParams[1] + loopVars[1])*33);
                require(copied);
                require(uint8(pk[0]) % 2 ==
                    utxos[_inputIDs[loopVars[0]*(ringParams[1]) + loopVars[1]]].pubkey.yBit % 2);    //yBit same
                //emit ParseBytes(utxos[_inputIDs[loopVars[0]*(ringParams[1]) + loopVars[1]]].pubkey.x, convertBytes33ToUint(pk,  1, 32), pk);
                require(convertBytes33ToUint(pk,  1, 32) ==
                    utxos[_inputIDs[loopVars[0]*(ringParams[1]) + loopVars[1]]].pubkey.x);
            }
        }


        //verify additional ring
        //compute sum of outputs
        uint256[2] memory outSum;
        outSum[0] = _outputs[0];
        outSum[1] = _outputs[1];
        for (i = 1; i < _outputs.length.div(6); i++) {
            (outSum[0], outSum[1]) = Secp256k1.add(outSum[0], outSum[1], _outputs[i*2], _outputs[i*2+1]);
        }

        for(loopVars[1] = 0; loopVars[1] < ringParams[1]; loopVars[1]++) {
            uint256[2] memory point = [uint256(0),uint256(0)];
            //compute sum of: all input pubkeys + all input commitments
            for(loopVars[0] = 0; loopVars[0] < ringParams[0] - 1; loopVars[0]++) {
                if (point[0] == uint256(0)) {
                    (point[0], point[1]) = Secp256k1.decompressXY(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.x);
                    uint256[2] memory commitment = Secp256k1.decompress(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.x);
                    (point[0], point[1]) = Secp256k1.add(point[0], point[1], commitment[0], commitment[1]);
                } else {
                    uint256[2] memory temp = Secp256k1.decompress(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].pubkey.x);
                    (point[0], point[1]) = Secp256k1.add(point[0], point[1], temp[0], temp[1]);
                    temp = Secp256k1.decompress(utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.yBit%2,
                        utxos[_inputIDs[loopVars[0]*ringParams[1] + loopVars[1]]].commitment.x);
                    (point[0], point[1]) = Secp256k1.add(point[0], point[1], temp[0], temp[1]);
                }
            }
            //sum - all output commitments
            (point[0], point[1]) = Secp256k1.sub(point[0], point[1], outSum[0], outSum[1]);
            (bool copied, byte[33] memory pk) = CopyUtils.Copy33Bytes(_ringSignature, ringParams[2] + ((ringParams[0] - 1)*ringParams[1] + loopVars[1])*33);
            require(copied);
            (uint8 ybit, uint256 compressX) = Secp256k1.compressXY(point[0], point[1]);
            //verify sum = the corresponding element in the last/additional ring
            //require(uint8(pk[0]) % 2 == yBit % 2);    //yBit same
            //require(convertBytes33ToUint(pk,  1, 32) == compressX);
        }

        //verify key image spend
        for(loopVars[0] = 0; loopVars[0] < ringParams[0]; loopVars[0]++) {
            (bool success, byte[33] memory ki) = CopyUtils.Copy33Bytes(_ringSignature, ringParams[3] + loopVars[0]*33);
            require(success);
            uint256 kiHash = bytesToUint(keccak256(abi.encodePacked(ki)));
            require(!keyImagesMapping[kiHash], "key image is spent!");
            keyImagesMapping[kiHash] = true;
        }

        //verify ringSignature
        require(VerifyRingCT(_ringSignature), "signature failed");

        require(_recipient != address(0x0), "recipient address invalid");
        _recipient.transfer(_withdrawalAmount);

        uint256[3] memory X;
        uint8[3] memory yBit;
        (yBit[0], X[0]) = Secp256k1.compressXY(_outputs[0], _outputs[1]);

        (yBit[1], X[1]) = Secp256k1.compressXY(_outputs[2], _outputs[3]);

        (yBit[2], X[2]) = Secp256k1.compressXY(_outputs[4], _outputs[5]);

        utxos.push(UTXO ({
            commitment: CompressPubKey(yBit[0] + 2, X[0]),
            pubkey: CompressPubKey(yBit[1] + 2, X[1]),
            amount: _amounts[0],
            txPub: CompressPubKey(yBit[2] + 2, X[2]),
            mask: _amounts[1]
            })
        );
        emit NewUTXO([utxos[utxos.length - 1].commitment.x, utxos[utxos.length - 1].pubkey.x, utxos[utxos.length - 1].txPub.x],
            [utxos[utxos.length - 1].commitment.yBit, utxos[utxos.length - 1].pubkey.yBit, utxos[utxos.length - 1].txPub.yBit],
            [utxos[utxos.length - 1].amount, utxos[utxos.length - 1].mask],
            utxos.length - 1);
    }
    function storeTxData(byte[] memory proof, bool parseOutput) private {
        uint8 rs = uint8(proof[0]);
        uint8 numInput = uint8(proof[1]);
        uint64 cursor = 2 + rs * numInput * 8;
        bytes memory ki = new bytes(33);
        for(i = 0; i < numInput; i++) {
            for(uint8 j = 0; j < 33; i++) {
                ki[j] = proof[cursor + i*33 + j];
            }
            //keyImages[uint256(keccak256(ki))] = true;
        }
    }

    function getUTXO(uint256 index) public view returns (uint256[3] memory,
        uint8[3] memory,
        uint256[2] memory //0. encrypted amount, 1. encrypted mask
    ) {
        return (
        [utxos[index].commitment.x, utxos[index].pubkey.x, utxos[index].txPub.x],
        [utxos[index].commitment.yBit, utxos[index].pubkey.yBit, utxos[index].txPub.yBit],
        [utxos[index].amount,utxos[index].mask]
        );
    }

    function isSpent(byte[] memory keyImage) public view returns (bool) {
        uint256 kiHash = bytesToUint(keccak256(abi.encodePacked(keyImage)));
        return keyImagesMapping[kiHash];
    }

    //dont receive any money via default callback
    function () external payable {
        revert();
    }
    function bytesToUint(bytes32 b) public view returns (uint256){
        uint256 number;
        for(uint256 j = 0;j < b.length; j++){
            number = number + (2**(8*(b.length-(j+1))))*uint256(uint8(b[j]));
        }
        return number;
    }

    function convertBytesToUint(bytes memory b, uint256 _start, uint256 _size) public returns (uint256){
        uint256 number;
        for(uint256 j = 0; j < _size; j++){
            number = number + (2**(8*(_size - (j+1))))*uint256(uint8(b[j + _start]));
        }
        return number;
    }

    function convertBytes33ToUint(byte[33] memory b, uint256 _start, uint256 _size) public returns (uint256){
        uint256 number;
        for(uint256 j = 0; j < _size; j++){
            number = number + (2**(8*(_size - (j+1))))*uint256(uint8(b[j + _start]));
        }
        return number;
    }
}