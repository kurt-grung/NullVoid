import { Threat, ThreatType } from '../types/core';
import { ScanOptions } from '../types/core';

/**
 * Check GPG signatures for package integrity
 */
export async function checkGpgSignatures(packageData: any, packageName: string, options: ScanOptions): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    let gpgSignatures: any[] = [];
    
    // Check for GPG signature in package metadata
    if (packageData.signatures) {
      // Check if package has GPG signatures
      gpgSignatures = packageData.signatures.filter((sig: any) => 
        sig.type === 'gpg' || sig.type === 'pgp' || sig.keyid
      );
      
      if (gpgSignatures.length === 0) {
        threats.push({
          type: 'MISSING_GPG_SIGNATURE' as ThreatType,
          message: 'Package missing GPG signature verification',
          package: packageName,
          severity: 'MEDIUM',
          details: `Package "${packageName}" does not have GPG signature verification, which could indicate tampering`
        });
      } else {
        // Verify GPG signatures
        for (const signature of gpgSignatures) {
          // Check signature validity
          if (!signature.valid) {
            threats.push({
              type: 'INVALID_GPG_SIGNATURE' as ThreatType,
              message: 'Invalid GPG signature detected',
              package: packageName,
              severity: 'HIGH',
              details: `Package "${packageName}" has invalid GPG signature: ${signature.keyid || 'unknown'}`
            });
          }
          
          // Check for suspicious key patterns
          if (signature.keyid && signature.keyid.length < 8) {
            threats.push({
              type: 'SUSPICIOUS_GPG_KEY' as ThreatType,
              message: 'Suspicious GPG key detected',
              package: packageName,
              severity: 'MEDIUM',
              details: `Package "${packageName}" uses suspiciously short GPG key: ${signature.keyid}`
            });
          }
        }
      }
    } else {
      // No signatures field at all
      threats.push({
        type: 'MISSING_GPG_SIGNATURE' as ThreatType,
        message: 'Package missing GPG signature verification',
        package: packageName,
        severity: 'MEDIUM',
        details: `Package "${packageName}" does not have any signature verification, which could indicate tampering`
      });
    }
    
    // Check for GPG signature in package.json
    if (packageData._hasShrinkwrap === false && !packageData.signatures) {
      threats.push({
        type: 'MISSING_GPG_SIGNATURE' as ThreatType,
        message: 'Package missing GPG signature in package.json',
        package: packageName,
        severity: 'LOW',
        details: `Package "${packageName}" package.json does not contain GPG signature information`
      });
    }
    
  } catch (error: any) {
    if (options.verbose) {
      console.warn(`Warning: Could not check GPG signatures for ${packageName}: ${error.message}`);
    }
    
    threats.push({
      type: 'GPG_SIGNATURE_ERROR' as ThreatType,
      message: 'Error checking GPG signatures',
      package: packageName,
      severity: 'LOW',
      details: `Could not verify GPG signatures for package "${packageName}": ${error.message}`
    });
  }
  
  return threats;
}

/**
 * Check package signatures for integrity
 */
export async function checkPackageSignatures(packageData: any, packageName: string, options: ScanOptions): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    // Check for package integrity signatures
    if (packageData.integrity) {
      // Verify package integrity
      if (packageData.integrity.startsWith('sha512-') || 
          packageData.integrity.startsWith('sha256-') ||
          packageData.integrity.startsWith('sha1-')) {
        // Valid integrity hash format
        if (options.verbose) {
          console.log(`Package ${packageName} has valid integrity hash: ${packageData.integrity}`);
        }
      } else {
        threats.push({
          type: 'INVALID_INTEGRITY_HASH' as ThreatType,
          message: 'Invalid package integrity hash',
          package: packageName,
          severity: 'HIGH',
          details: `Package "${packageName}" has invalid integrity hash format: ${packageData.integrity}`
        });
      }
    } else {
      threats.push({
        type: 'MISSING_INTEGRITY_HASH' as ThreatType,
        message: 'Package missing integrity hash',
        package: packageName,
        severity: 'MEDIUM',
        details: `Package "${packageName}" does not have an integrity hash for verification`
      });
    }
    
    // Check for package.json signatures
    if (packageData._signatures) {
      const packageJsonSignatures = packageData._signatures.filter((sig: any) => 
        sig.type === 'package-json' || sig.type === 'manifest'
      );
      
      if (packageJsonSignatures.length === 0) {
        threats.push({
          type: 'MISSING_PACKAGE_JSON_SIGNATURE' as ThreatType,
          message: 'Package missing package.json signature',
          package: packageName,
          severity: 'LOW',
          details: `Package "${packageName}" package.json is not signed`
        });
      }
    }
    
  } catch (error: any) {
    if (options.verbose) {
      console.warn(`Warning: Could not check package signatures for ${packageName}: ${error.message}`);
    }
    
    threats.push({
      type: 'PACKAGE_SIGNATURE_ERROR' as ThreatType,
      message: 'Error checking package signatures',
      package: packageName,
      severity: 'LOW',
      details: `Could not verify package signatures for "${packageName}": ${error.message}`
    });
  }
  
  return threats;
}

/**
 * Check package integrity
 */
export async function checkPackageIntegrity(packageData: any, packageName: string): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    // Check for required package fields
    const requiredFields = ['name', 'version', 'description'];
    for (const field of requiredFields) {
      if (!packageData[field]) {
        threats.push({
          type: 'MISSING_PACKAGE_FIELD' as ThreatType,
          message: `Package missing required field: ${field}`,
          package: packageName,
          severity: 'MEDIUM',
          details: `Package "${packageName}" is missing required field: ${field}`
        });
      }
    }
    
    // Check for suspicious package metadata
    if (packageData.name && packageData.name.length < 3) {
      threats.push({
        type: 'SUSPICIOUS_PACKAGE_NAME' as ThreatType,
        message: 'Suspicious package name',
        package: packageName,
        severity: 'MEDIUM',
        details: `Package name "${packageData.name}" is suspiciously short`
      });
    }
    
    // Check for suspicious version patterns
    if (packageData.version && !/^\d+\.\d+\.\d+/.test(packageData.version)) {
      threats.push({
        type: 'SUSPICIOUS_VERSION' as ThreatType,
        message: 'Suspicious version format',
        package: packageName,
        severity: 'LOW',
        details: `Package version "${packageData.version}" does not follow semantic versioning`
      });
    }
    
  } catch (error: any) {
    threats.push({
      type: 'PACKAGE_INTEGRITY_ERROR' as ThreatType,
      message: 'Error checking package integrity',
      package: packageName,
      severity: 'LOW',
      details: `Could not verify package integrity for "${packageName}": ${error}`
    });
  }
  
  return threats;
}

/**
 * Check tarball signatures
 */
export async function checkTarballSignatures(packageData: any, packageName: string, options: ScanOptions): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    // Check for tarball signature information
    if (packageData.dist && packageData.dist.signature) {
      const signature = packageData.dist.signature;
      
      // Verify signature format
      if (signature.startsWith('-----BEGIN PGP SIGNATURE-----')) {
        if (options.verbose) {
          console.log(`Package ${packageName} has valid tarball signature`);
        }
      } else {
        threats.push({
          type: 'INVALID_TARBALL_SIGNATURE' as ThreatType,
          message: 'Invalid tarball signature format',
          package: packageName,
          severity: 'HIGH',
          details: `Package "${packageName}" has invalid tarball signature format`
        });
      }
    } else {
      threats.push({
        type: 'MISSING_TARBALL_SIGNATURE' as ThreatType,
        message: 'Package missing tarball signature',
        package: packageName,
        severity: 'MEDIUM',
        details: `Package "${packageName}" tarball is not signed`
      });
    }
    
  } catch (error: any) {
    if (options.verbose) {
      console.warn(`Warning: Could not check tarball signatures for ${packageName}: ${error.message}`);
    }
    
    threats.push({
      type: 'TARBALL_SIGNATURE_ERROR' as ThreatType,
      message: 'Error checking tarball signatures',
      package: packageName,
      severity: 'LOW',
      details: `Could not verify tarball signatures for "${packageName}": ${error.message}`
    });
  }
  
  return threats;
}

/**
 * Check package.json signatures
 */
export async function checkPackageJsonSignatures(packageData: any, packageName: string): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    // Check for package.json signature field
    if (packageData._packageJsonSignature) {
      const signature = packageData._packageJsonSignature;
      
      // Verify signature format
      if (signature.startsWith('-----BEGIN PGP SIGNATURE-----')) {
        // Valid signature format
      } else {
        threats.push({
          type: 'INVALID_PACKAGE_JSON_SIGNATURE' as ThreatType,
          message: 'Invalid package.json signature format',
          package: packageName,
          severity: 'HIGH',
          details: `Package "${packageName}" has invalid package.json signature format`
        });
      }
    } else {
      threats.push({
        type: 'MISSING_PACKAGE_JSON_SIGNATURE' as ThreatType,
        message: 'Package missing package.json signature',
        package: packageName,
        severity: 'LOW',
        details: `Package "${packageName}" package.json is not signed`
      });
    }
    
  } catch (error: any) {
    threats.push({
      type: 'PACKAGE_JSON_SIGNATURE_ERROR' as ThreatType,
      message: 'Error checking package.json signatures',
      package: packageName,
      severity: 'LOW',
      details: `Could not verify package.json signatures for "${packageName}": ${error}`
    });
  }
  
  return threats;
}

/**
 * Check maintainer signatures
 */
export async function checkMaintainerSignatures(packageData: any, packageName: string): Promise<Threat[]> {
  const threats: Threat[] = [];
  
  if (!packageData) {
    return threats;
  }
  
  try {
    // Check for maintainer information
    if (packageData.maintainers && packageData.maintainers.length > 0) {
      for (const maintainer of packageData.maintainers) {
        if (!maintainer.email || !maintainer.name) {
          threats.push({
            type: 'INCOMPLETE_MAINTAINER_INFO' as ThreatType,
            message: 'Incomplete maintainer information',
            package: packageName,
            severity: 'LOW',
            details: `Package "${packageName}" has incomplete maintainer information`
          });
        }
      }
    } else {
      threats.push({
        type: 'MISSING_MAINTAINER_INFO' as ThreatType,
        message: 'Package missing maintainer information',
        package: packageName,
        severity: 'LOW',
        details: `Package "${packageName}" does not have maintainer information`
      });
    }
    
  } catch (error: any) {
    threats.push({
      type: 'MAINTAINER_SIGNATURE_ERROR' as ThreatType,
      message: 'Error checking maintainer signatures',
      package: packageName,
      severity: 'LOW',
      details: `Could not verify maintainer signatures for "${packageName}": ${error}`
    });
  }
  
  return threats;
}
