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

// Version information
export const VERSION = '1.0.0';
