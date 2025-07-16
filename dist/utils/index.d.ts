/**
 * Utility functions for Verifiable Credentials
 */
import { VerifiableCredential, VerifiablePresentation, URI, DateTime } from '../types';
/**
 * Generate a unique URI for credentials or presentations
 */
export declare function generateURI(prefix?: string): URI;
/**
 * Get current ISO 8601 datetime string
 */
export declare function getCurrentDateTime(): DateTime;
/**
 * Check if a string is a valid URI
 */
export declare function isValidURI(uri: string): boolean;
/**
 * Check if a string is a valid ISO 8601 datetime
 */
export declare function isValidDateTime(dateTime: string): boolean;
/**
 * Extract issuer URI from credential
 */
export declare function getIssuerURI(credential: VerifiableCredential): URI;
/**
 * Extract holder URI from presentation
 */
export declare function getHolderURI(presentation: VerifiablePresentation): URI | undefined;
/**
 * Get all subject IDs from a credential
 */
export declare function getSubjectIDs(credential: VerifiableCredential): (URI | undefined)[];
/**
 * Check if credential has a specific type
 */
export declare function hasCredentialType(credential: VerifiableCredential, type: string): boolean;
/**
 * Check if presentation has a specific type
 */
export declare function hasPresentationType(presentation: VerifiablePresentation, type: string): boolean;
/**
 * Check if credential is currently valid (not expired)
 */
export declare function isCredentialValid(credential: VerifiableCredential): boolean;
/**
 * Get credentials from presentation
 */
export declare function getCredentialsFromPresentation(presentation: VerifiablePresentation): VerifiableCredential[];
/**
 * Filter credentials by type
 */
export declare function filterCredentialsByType(credentials: VerifiableCredential[], type: string): VerifiableCredential[];
/**
 * Filter credentials by issuer
 */
export declare function filterCredentialsByIssuer(credentials: VerifiableCredential[], issuerURI: URI): VerifiableCredential[];
/**
 * Filter valid (non-expired) credentials
 */
export declare function filterValidCredentials(credentials: VerifiableCredential[]): VerifiableCredential[];
/**
 * Deep clone an object
 */
export declare function deepClone<T>(obj: T): T;
/**
 * Merge contexts from multiple sources
 */
export declare function mergeContexts(...contexts: (string | string[])[]): string[];
/**
 * Normalize types to always be an array
 */
export declare function normalizeTypes(types: string | string[]): string[];
/**
 * Check if two arrays have the same elements (order independent)
 */
export declare function arraysEqual<T>(a: T[], b: T[]): boolean;
/**
 * Sanitize a string for use as an identifier
 */
export declare function sanitizeIdentifier(str: string): string;
/**
 * Create a simple hash of a string
 */
export declare function simpleHash(str: string): string;
/**
 * Convert credential to JSON string with proper formatting
 */
export declare function credentialToJSON(credential: VerifiableCredential, indent?: number): string;
/**
 * Convert presentation to JSON string with proper formatting
 */
export declare function presentationToJSON(presentation: VerifiablePresentation, indent?: number): string;
/**
 * Parse JSON string to credential with validation
 */
export declare function parseCredentialFromJSON(json: string): VerifiableCredential;
/**
 * Parse JSON string to presentation with validation
 */
export declare function parsePresentationFromJSON(json: string): VerifiablePresentation;
//# sourceMappingURL=index.d.ts.map