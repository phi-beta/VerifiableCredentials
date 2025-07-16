/**
 * Core types and interfaces for W3C Verifiable Credentials Data Model v2.0
 * Based on: https://www.w3.org/TR/vc-data-model/
 */

// Basic W3C Data Model types
export type URI = string;
export type DateTime = string; // ISO 8601 date-time
export type ID = string;

// Core Verifiable Credential structure
export interface VerifiableCredential {
  '@context': string | string[];
  id?: ID;
  type: string | string[];
  issuer: URI | Issuer;
  validFrom?: DateTime;
  validUntil?: DateTime;
  credentialSubject: CredentialSubject | CredentialSubject[];
  proof?: Proof | Proof[];
  
  // Optional properties
  credentialStatus?: CredentialStatus;
  credentialSchema?: CredentialSchema;
  refreshService?: RefreshService;
  termsOfUse?: TermsOfUse[];
  evidence?: Evidence[];
}

// Verifiable Presentation structure
export interface VerifiablePresentation {
  '@context': string | string[];
  id?: ID;
  type: string | string[];
  verifiableCredential?: VerifiableCredential[];
  holder?: URI;
  proof?: Proof | Proof[];
  
  // Optional properties
  termsOfUse?: TermsOfUse[];
}

// Issuer can be a URI or an object with additional properties
export interface Issuer {
  id: URI;
  name?: string;
  description?: string;
  url?: URI;
  image?: URI;
  [key: string]: any;
}

// Credential Subject - the entity about which claims are made
export interface CredentialSubject {
  id?: URI;
  [key: string]: any;
}

// Proof mechanisms for securing credentials
export interface Proof {
  type: string;
  created?: DateTime;
  verificationMethod?: URI;
  proofPurpose?: string;
  challenge?: string;
  domain?: string;
  proofValue?: string;
  jws?: string;
  [key: string]: any;
}

// Credential Status for revocation checks
export interface CredentialStatus {
  id: URI;
  type: string;
  statusPurpose?: string;
  statusListIndex?: string;
  statusListCredential?: URI;
  [key: string]: any;
}

// Credential Schema for validation
export interface CredentialSchema {
  id: URI;
  type: string;
  [key: string]: any;
}

// Refresh Service for credential updates
export interface RefreshService {
  id: URI;
  type: string;
  [key: string]: any;
}

// Terms of Use
export interface TermsOfUse {
  type: string;
  id?: URI;
  profile?: URI;
  prohibition?: Prohibition[];
  [key: string]: any;
}

export interface Prohibition {
  assigner?: URI;
  assignee?: URI;
  target?: URI;
  action?: string[];
  [key: string]: any;
}

// Evidence for credential claims
export interface Evidence {
  id?: URI;
  type: string[];
  [key: string]: any;
}

// Common validation result
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings?: string[];
}
