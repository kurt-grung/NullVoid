/**
 * Package-specific type definitions
 */

export interface PackageInfo {
  /** Package name */
  name: string;
  /** Package version */
  version: string;
  /** Package description */
  description?: string;
  /** Package author */
  author?: string | AuthorInfo;
  /** Package license */
  license?: string;
  /** Package repository */
  repository?: string | RepositoryInfo;
  /** Package homepage */
  homepage?: string;
  /** Package keywords */
  keywords?: string[];
  /** Package dependencies */
  dependencies?: Record<string, string>;
  /** Package dev dependencies */
  devDependencies?: Record<string, string>;
  /** Package scripts */
  scripts?: Record<string, string>;
  /** Package main entry point */
  main?: string;
  /** Package bin executables */
  bin?: string | Record<string, string>;
}

export interface AuthorInfo {
  name: string;
  email?: string;
  url?: string;
}

export interface RepositoryInfo {
  type: string;
  url: string;
  directory?: string;
}

export interface PackageMetadata {
  /** Package information */
  package: PackageInfo;
  /** Package tarball URL */
  tarballUrl: string;
  /** Package signature URL */
  signatureUrl?: string;
  /** Package integrity hash */
  integrity?: string;
  /** Package publish date */
  publishedAt: Date;
  /** Package maintainers */
  maintainers: MaintainerInfo[];
  /** Package downloads count */
  downloads: number;
}

export interface MaintainerInfo {
  name: string;
  email: string;
  url?: string;
}
