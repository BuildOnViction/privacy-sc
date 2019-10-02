// pragma solidity 0.4.24;

// contract PrivacyRegistry {
//     mapping(address => bytes) normalAddressToPrivacyAddress;
//     mapping(bytes => address) privacyAddressToNormalAddress;
//     function register(bytes _privacyAddress) external {
//         normalAddressToPrivacyAddress[msg.sender] = _privacyAddress;
//         privacyAddressToNormalAddress[_privacyAddress] = msg.sender;
//     }

//     function getPrivacyAddress(address _normal) external view returns (bytes) {
//         return normalAddressToPrivacyAddress[_normal];
//     }

//     function getNormalAddress(bytes _privacy) external view returns (address) {
//         return privacyAddressToNormalAddress[_privacy];
//     }
// }