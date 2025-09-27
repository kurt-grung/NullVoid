/**
 * Placeholder secure error handler module - will be migrated next
 */

import { SecurityError, ValidationError } from '../types';

export class InputValidator {
  static validatePackageName(packageName: string): string {
    // Basic validation
    if (!packageName || typeof packageName !== 'string') {
      throw new ValidationError('Package name must be a non-empty string');
    }
    
    if (packageName.length > 214) {
      throw new ValidationError('Package name too long');
    }
    
    return packageName;
  }
  
  static validateScanOptions(options: any): any {
    // Basic validation
    if (options.output && !['json', 'table', 'yaml', 'sarif'].includes(options.output)) {
      throw new ValidationError('Invalid output format');
    }
    
    return options;
  }
}

export { SecurityError, ValidationError };
