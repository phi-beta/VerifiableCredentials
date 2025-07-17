/**
 * W3C Verifiable Credentials TypeScript Implementation
 * Main entry point for the library
 */
export * from './types';
export * from './context';
export * from './security';
export { Issuer } from './roles/issuer';
export { Holder } from './roles/holder';
export { Verifier } from './roles/verifier';
export { ValidationEngine } from './validation';
export { SchemaValidator, schemaValidator } from './schema';
export * from './utils';
export { OIDC4VCIServer, OIDC4VPServer, OIDC4VCClient, type OIDC4VCIConfig, type OIDC4VPConfig, type CredentialOffer, type CredentialRequest, type CredentialResponse, type PresentationRequest, type AuthorizationResponse } from './oidc4vc';
export declare const VERSION = "1.0.0";
//# sourceMappingURL=index.d.ts.map