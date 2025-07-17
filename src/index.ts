/**
 * W3C Verifiable Credentials TypeScript Implementation
 * Main entry point for the library
 */

// Core types and interfaces
export * from './types';

// JSON-LD Context management
export * from './context';

// Security and cryptographic operations
export * from './security';

// Role implementations
export { Issuer } from './roles/issuer';
export { Holder } from './roles/holder';
export { Verifier } from './roles/verifier';

// Validation engine
export { ValidationEngine } from './validation';

// Schema validation
export { SchemaValidator, schemaValidator } from './schema';

// Utility functions
export * from './utils';

// OIDC4VC (OpenID Connect for Verifiable Credentials)
export { 
  OIDC4VCIServer, 
  OIDC4VPServer, 
  OIDC4VCClient,
  type OIDC4VCIConfig,
  type OIDC4VPConfig,
  type CredentialOffer,
  type CredentialRequest,
  type CredentialResponse,
  type PresentationRequest,
  type AuthorizationResponse
} from './oidc4vc';

// Version information
export const VERSION = '1.0.0';
