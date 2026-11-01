/**
 * Blockchain verification for package CIDs
 *
 * Registers and retrieves package CIDs on EVM-compatible chains (Polygon, Base, etc.)
 * Requires viem package: npm install viem
 *
 * When viem is not installed, functions throw a clear error.
 */

export interface BlockchainConfig {
  ENABLED?: boolean;
  RPC_URL?: string;
  CONTRACT_ADDRESS?: string | null;
  PRIVATE_KEY?: string | null;
  CHAIN_ID?: number;
}

const DEFAULT_CONFIG: BlockchainConfig = {
  ENABLED: false,
  RPC_URL: 'https://polygon-rpc.com',
  CONTRACT_ADDRESS: null,
  PRIVATE_KEY: null,
  CHAIN_ID: 137,
};

const ABI = [
  'function registerPackage(string calldata pkg, string calldata version, string calldata cid) external',
  'function getCid(string calldata pkg, string calldata version) external view returns (string memory)',
  'function hasCid(string calldata pkg, string calldata version) external view returns (bool)',
] as const;

/**
 * Register package CID on-chain
 */
export async function registerPackageOnChain(
  pkg: string,
  version: string,
  cid: string,
  config: Partial<BlockchainConfig> = {}
): Promise<{ txHash: string }> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  if (!cfg.CONTRACT_ADDRESS || !cfg.PRIVATE_KEY) {
    throw new Error('CONTRACT_ADDRESS and PRIVATE_KEY required for registerPackageOnChain');
  }

  try {
    // Dynamic require - viem is optional. Install with: npm install viem
    const viem = require('viem') as {
      createWalletClient: (opts: { account: unknown; chain: unknown; transport: unknown }) => {
        writeContract: (opts: unknown) => Promise<string>;
      };
      http: (url: string) => unknown;
    };
    const accounts = require('viem/accounts') as {
      privateKeyToAccount: (k: `0x${string}`) => unknown;
    };
    const chains = require('viem/chains') as { polygon: unknown };

    const account = accounts.privateKeyToAccount(cfg.PRIVATE_KEY as `0x${string}`);
    const walletClient = viem.createWalletClient({
      account,
      chain: chains.polygon,
      transport: viem.http(cfg.RPC_URL ?? 'https://polygon-rpc.com'),
    });

    const hash = await walletClient.writeContract({
      address: cfg.CONTRACT_ADDRESS as `0x${string}`,
      abi: ABI,
      functionName: 'registerPackage',
      args: [pkg, version, cid],
      account,
    });

    return { txHash: hash };
  } catch (err) {
    if (err instanceof Error && err.message.includes('Cannot find module')) {
      throw new Error(
        'viem package required for blockchain verification. Install with: npm install viem'
      );
    }
    throw err;
  }
}

/**
 * Get CID from chain
 */
export async function getCidFromChain(
  pkg: string,
  version: string,
  config: Partial<BlockchainConfig> = {}
): Promise<string | null> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  if (!cfg.CONTRACT_ADDRESS) {
    throw new Error('CONTRACT_ADDRESS required for getCidFromChain');
  }

  try {
    const viem = require('viem') as {
      createPublicClient: (opts: { chain: unknown; transport: unknown }) => {
        readContract: (opts: unknown) => Promise<string>;
      };
      http: (url: string) => unknown;
    };
    const chains = require('viem/chains') as { polygon: unknown };

    const publicClient = viem.createPublicClient({
      chain: chains.polygon,
      transport: viem.http(cfg.RPC_URL ?? 'https://polygon-rpc.com'),
    });

    const cid = await publicClient.readContract({
      address: cfg.CONTRACT_ADDRESS as `0x${string}`,
      abi: ABI,
      functionName: 'getCid',
      args: [pkg, version],
    });

    return typeof cid === 'string' && cid.length > 0 ? cid : null;
  } catch (err) {
    if (err instanceof Error && err.message.includes('Cannot find module')) {
      throw new Error(
        'viem package required for blockchain verification. Install with: npm install viem'
      );
    }
    throw err;
  }
}

/**
 * Verify package CID against chain
 */
export async function verifyPackageOnChain(
  pkg: string,
  version: string,
  cid: string,
  config: Partial<BlockchainConfig> = {}
): Promise<boolean> {
  const chainCid = await getCidFromChain(pkg, version, config);
  return chainCid !== null && chainCid === cid;
}
