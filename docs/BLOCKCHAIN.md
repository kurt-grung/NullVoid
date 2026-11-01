# Blockchain Verification

NullVoid supports on-chain storage of package CIDs for decentralized integrity verification.

## Requirements

- **viem**: Install with `npm install viem` (optional dependency)
- **Contract**: Deploy `contracts/NullVoidRegistry.sol` to your chain
- **Wallet**: Private key for registering packages

## Configuration

```json
{
  "DEPENDENCY_CONFUSION_CONFIG": {
    "BLOCKCHAIN_CONFIG": {
      "ENABLED": true,
      "RPC_URL": "https://polygon-rpc.com",
      "CONTRACT_ADDRESS": "0x...",
      "PRIVATE_KEY": "0x...",
      "CHAIN_ID": 137
    }
  }
}
```

Environment variables:
- `NULLVOID_BLOCKCHAIN_ENABLED=true`
- `NULLVOID_BLOCKCHAIN_RPC_URL`
- `NULLVOID_BLOCKCHAIN_CONTRACT_ADDRESS`
- `NULLVOID_BLOCKCHAIN_PRIVATE_KEY`
- `NULLVOID_BLOCKCHAIN_CHAIN_ID` (default: 137 for Polygon)

## CLI Commands

### register-on-chain

Compute CID for a package tarball and register on blockchain:

```bash
npm pack
nullvoid register-on-chain nullvoid-2.1.0.tgz
```

### verify-on-chain

Verify package CID against blockchain:

```bash
nullvoid verify-on-chain lodash@4.17.21 --cid bafy...
```

## Contract

Deploy `contracts/NullVoidRegistry.sol` to Polygon, Base, or any EVM chain. The contract stores `package@version` mappings to IPFS CIDs.

```solidity
function registerPackage(string calldata pkg, string calldata version, string calldata cid) external;
function getCid(string calldata pkg, string calldata version) external view returns (string memory);
```
