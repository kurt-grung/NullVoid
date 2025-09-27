import { Threat, ThreatType } from '../types/core';
import { downloadPackageFiles } from './packageAnalysis';

/**
 * Check for wallet hijacking patterns in content
 */
export function checkWalletHijackingInContent(content: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  // Check for window.ethereum manipulation
  if (content.includes('window.ethereum') && 
      (content.includes('Proxy') || content.includes('Object.defineProperty'))) {
    threats.push({
      type: 'WALLET_HIJACKING' as ThreatType,
      severity: 'CRITICAL',
      package: packageName,
      message: 'Detected window.ethereum manipulation - potential wallet hijacking',
      details: 'Detected window.ethereum manipulation - potential wallet hijacking'
    });
  }
  
  // Check for MetaMask specific patterns
  if (content.includes('MetaMask') || content.includes('ethereum.request')) {
    threats.push({
      type: 'WALLET_HIJACKING' as ThreatType,
      severity: 'HIGH',
      package: packageName,
      message: 'Detected MetaMask/ethereum interaction patterns',
      details: 'Detected MetaMask/ethereum interaction patterns'
    });
  }
  
  return threats;
}

/**
 * Check for network manipulation patterns in content
 */
export function checkNetworkManipulationInContent(content: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  // Check for fetch/XMLHttpRequest overrides
  if ((content.includes('fetch') || content.includes('XMLHttpRequest')) &&
      (content.includes('Proxy') || content.includes('override'))) {
    threats.push({
      type: 'NETWORK_MANIPULATION' as ThreatType,
      severity: 'HIGH',
      package: packageName,
      message: 'Detected network request manipulation',
      details: 'Detected network request manipulation'
    });
  }
  
  // Check for suspicious URLs
  const suspiciousUrls = [
    'http://', 'https://', 'ws://', 'wss://'
  ];
  
  for (const url of suspiciousUrls) {
    if (content.includes(url)) {
      threats.push({
        type: 'NETWORK_MANIPULATION' as ThreatType,
        severity: 'MEDIUM',
        package: packageName,
        message: 'Detected suspicious network communication',
        details: `Detected suspicious URL pattern: ${url}`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Check for stealth controls and obfuscation patterns in content
 */
export function checkStealthControlsInContent(content: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  // Check for anti-debugging techniques
  const stealthPatterns = [
    'debugger',
    'console.clear',
    'console.log.*override',
    'setInterval.*clear',
    'performance.now',
    'Date.now.*override'
  ];
  
  for (const pattern of stealthPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'STEALTH_CONTROLS' as ThreatType,
        severity: 'MEDIUM',
        package: packageName,
        message: 'Detected stealth/anti-debugging patterns',
        details: `Detected stealth pattern: ${pattern}`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Check for obfuscated IoCs (Indicators of Compromise)
 */
export function checkObfuscatedIoCs(content: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  // Check for obfuscated URLs, IPs, and domains
  const iocPatterns = [
    /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
    /[a-zA-Z0-9.-]+\.(?:com|org|net|io|co|me|us|uk|de|fr|jp|cn|ru|br|au|ca|in|mx|es|it|nl|se|no|dk|fi|pl|tr|za|eg|ng|ke|ma|dz|tn|ly|sd|so|et|ug|rw|bi|mw|zm|bw|sz|ls|mg|mu|sc|km|dj|er|ss|cf|td|ne|ml|bf|ci|gh|tg|bj|sn|gm|gn|gw|sl|lr|cv|st|ao|cd|cg|ga|gq|cm|cf|td|ne|ml|bf|ci|gh|tg|bj|sn|gm|gn|gw|sl|lr|cv|st|ao|cd|cg|ga|gq|cm)/g
  ];
  
  for (const pattern of iocPatterns) {
    const matches = content.match(pattern);
    if (matches && matches.length > 0) {
      threats.push({
        type: 'OBFUSCATED_IOC' as ThreatType,
        severity: 'HIGH',
        package: packageName,
        message: 'Obfuscated DOMAINS detected',
        details: `Detected obfuscated DOMAINS which could be used for malicious communication`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Detect dynamic require() patterns
 */
export function detectDynamicRequires(code: string, packageName: string): Threat[] {
  const threats: Threat[] = [];
  
  // Check for dynamic require patterns
  const dynamicRequirePatterns = [
    /require\s*\(\s*['"`][^'"`]*\$\{.*\}.*['"`]\s*\)/g,
    /require\s*\(\s*[^'"`]*\+.*['"`]\s*\)/g,
    /eval\s*\(\s*['"`].*require.*['"`]\s*\)/g,
    /Function\s*\(\s*['"`].*require.*['"`]\s*\)/g
  ];
  
  for (const pattern of dynamicRequirePatterns) {
    if (pattern.test(code)) {
      threats.push({
        type: 'DYNAMIC_REQUIRE' as ThreatType,
        severity: 'HIGH',
        package: packageName,
        message: 'Dynamic require() detected',
        details: 'Detected dynamic require() patterns that could load malicious modules'
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Check for wallet hijacking patterns in package data
 */
export async function checkWalletHijacking(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  // Real IoCs from the recent npm compromise
  const walletHijackingPatterns = [
    'window.ethereum',
    'ethereum.request',
    'eth_sendTransaction',
    'eth_signTransaction',
    'MetaMask',
    'Web3Provider',
    'transaction.*redirect',
    'address.*replace',
    'stealthProxyControl',
    '_0x112fa8',
    '_0x180f',
    '_0x20669a',
    'runmask',
    'newdlocal',
    'checkethereumw'
  ];
  
  // Check for wallet hijacking patterns
  for (const pattern of walletHijackingPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'WALLET_HIJACKING' as ThreatType,
        message: 'Package may contain wallet hijacking code that intercepts blockchain transactions',
        package: packageData.name || 'unknown',
        severity: 'CRITICAL',
        details: `Detected pattern '${pattern}' that could redirect transactions to attacker-controlled addresses`
      });
      break; // Only report once per package
    }
  }
  
  return threats;
}

/**
 * Detect network response manipulation (fetch/XMLHttpRequest overrides)
 */
export async function checkNetworkManipulation(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  // Check for network manipulation patterns
  const networkPatterns = [
    'fetch.*override',
    'XMLHttpRequest.*override',
    'XMLHttpRequest.*prototype',
    'fetch.*prototype',
    'response.*replace',
    'request.*intercept',
    'proxy.*http',
    'mitm',
    'man-in-the-middle'
  ];
  
  for (const pattern of networkPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'NETWORK_MANIPULATION' as ThreatType,
        message: 'Package may contain network manipulation code',
        package: packageData.name || 'unknown',
        severity: 'HIGH',
        details: `Detected network manipulation pattern: ${pattern}`
      });
      break;
    }
  }
  
  return threats;
}

/**
 * Check for multi-chain targeting (Ethereum, BSC, Polygon, etc.)
 */
export async function checkMultiChainTargeting(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  // Check for multi-chain patterns
  const multiChainPatterns = [
    'ethereum',
    'bsc',
    'binance',
    'polygon',
    'matic',
    'avalanche',
    'fantom',
    'arbitrum',
    'optimism',
    'chainId',
    'networkId',
    'web3.*provider',
    'walletconnect',
    'walletlink'
  ];
  
  let chainCount = 0;
  for (const pattern of multiChainPatterns) {
    if (content.toLowerCase().includes(pattern.toLowerCase())) {
      chainCount++;
    }
  }
  
  if (chainCount >= 3) {
    threats.push({
      type: 'MULTI_CHAIN_TARGETING' as ThreatType,
      message: 'Package targets multiple blockchain networks',
      package: packageData.name || 'unknown',
      severity: 'HIGH',
      details: `Detected targeting of ${chainCount} different blockchain networks`
    });
  }
  
  return threats;
}

/**
 * Check for stealth controls and obfuscation
 */
export async function checkStealthControls(packageData: any): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  const content = await downloadPackageFiles(packageData);
  
  // Check for stealth patterns
  const stealthPatterns = [
    'debugger.*disable',
    'console.*clear',
    'performance.*override',
    'Date.*override',
    'setTimeout.*clear',
    'setInterval.*clear',
    'requestAnimationFrame.*override',
    'webpack.*require',
    'babel.*transform',
    'uglify',
    'minify',
    'obfuscate'
  ];
  
  for (const pattern of stealthPatterns) {
    if (content.includes(pattern)) {
      threats.push({
        type: 'STEALTH_CONTROLS' as ThreatType,
        message: 'Package contains stealth/anti-debugging techniques',
        package: packageData.name || 'unknown',
        severity: 'MEDIUM',
        details: `Detected stealth pattern: ${pattern}`
      });
      break;
    }
  }
  
  return threats;
}
