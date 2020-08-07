pragma solidity ^0.5.0;

library CopyUtils {
    function Copy33Bytes(bytes memory data, uint256 _start) internal view returns (bool success, byte[33] memory ret) {
        if (data.length < _start + 33) {
            success = false;
        } else {
            for (uint256 i = _start; i < _start + 33; i++) {
                ret[i - _start] = data[i];
            }
            success = true;
        }
    }

    function Copy32Bytes(bytes memory data, uint256 _start) internal view returns (bool success, byte[32] memory ret) {
        if (data.length < _start + 32) {
            success = false;
        } else {
            for (uint256 i = _start; i < _start + 32; i++) {
                ret[i - _start] = data[i];
            }
            success = true;
        }
    }

    function Copy32Bytes2(bytes memory data, uint256 _start) internal view returns (bool success, byte[32] memory ret) {
        if (data.length < _start + 32) {
            success = false;
        } else {
            for (uint256 i = _start; i < _start + 32; i++) {
                ret[i - _start] = data[i];
            }
            success = true;
        }
    }

    function CompareBytes(bytes32 b1, bytes memory b2, uint256 _start) internal view returns (bool) {
        for (uint8 i = 0; i < 32; i++) {
            if (b1[i] != b2[_start + i]) return false;
        }
        return true;
    }

    function CopyBytes(bytes memory data, uint256 _start, uint256 _size) internal view returns (bool, byte[] memory) {
        byte[] memory ret;
        if (data.length < _start + _size) {
            return (false, ret);
        } else {
            ret = new byte[](_size);
            for (uint256 i = _start; i < _start + _size; i++) {
                ret[i - _start] = data[i];
            }
            return (true, ret);
        }
    }

    function BytesToUint(bytes32 b) internal view returns (uint256){
        uint256 number;
        for(uint256 j = 0;j < b.length; j++){
            number = number + (2**(8*(b.length-(j+1))))*uint256(uint8(b[j]));
        }
        return number;
    }

    function ConvertBytesToUint(bytes memory b, uint256 _start, uint256 _size) internal view returns (uint256){
        uint256 number;
        for(uint256 j = 0; j < _size; j++){
            number = number + (2**(8*(_size - (j+1))))*uint256(uint8(b[j + _start]));
        }
        return number;
    }

    function ConvertBytes33ToUint(byte[33] memory b, uint256 _start, uint256 _size) internal view returns (uint256){
        uint256 number;
        for(uint256 j = 0; j < _size; j++){
            number = number + (2**(8*(_size - (j+1))))*uint256(uint8(b[j + _start]));
        }
        return number;
    }
}

