// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * NullVoidRegistry - On-chain storage of package CIDs for integrity verification
 *
 * Maps package@version to IPFS CID. Enables decentralized verification of
 * npm package integrity.
 */
contract NullVoidRegistry {
    mapping(bytes32 => string) public packageCids;

    event PackageRegistered(string indexed pkg, string indexed version, string cid);

    function _key(string calldata pkg, string calldata version) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(pkg, "@", version));
    }

    function registerPackage(
        string calldata pkg,
        string calldata version,
        string calldata cid
    ) external {
        bytes32 k = _key(pkg, version);
        packageCids[k] = cid;
        emit PackageRegistered(pkg, version, cid);
    }

    function getCid(
        string calldata pkg,
        string calldata version
    ) external view returns (string memory) {
        return packageCids[_key(pkg, version)];
    }

    function hasCid(string calldata pkg, string calldata version) external view returns (bool) {
        bytes32 k = _key(pkg, version);
        return bytes(packageCids[k]).length > 0;
    }
}
