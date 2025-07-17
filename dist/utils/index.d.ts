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
/**
 * Advanced date/time utilities
 */
/**
 * Add time duration to a date
 */
export declare function addDuration(dateTime: DateTime, duration: {
    years?: number;
    months?: number;
    days?: number;
    hours?: number;
    minutes?: number;
}): DateTime;
/**
 * Check if a date is expired
 */
export declare function isExpired(expirationDate: DateTime): boolean;
/**
 * Check if a date is in the future (not yet valid)
 */
export declare function isFuture(validFromDate: DateTime): boolean;
/**
 * Get time until expiration in milliseconds
 */
export declare function getTimeUntilExpiration(expirationDate: DateTime): number;
/**
 * Format duration in human readable format
 */
export declare function formatDuration(milliseconds: number): string;
/**
 * Advanced URI utilities
 */
/**
 * Generate a DID-style URI
 */
export declare function generateDID(method?: string, identifier?: string): URI;
/**
 * Parse DID components
 */
export declare function parseDID(did: string): {
    method: string;
    identifier: string;
    path?: string;
    query?: string;
    fragment?: string;
} | null;
/**
 * Generate a credential ID with prefix
 */
export declare function generateCredentialID(issuerDomain: string): URI;
/**
 * Generate a presentation ID
 */
export declare function generatePresentationID(holderDomain?: string): URI;
/**
 * Advanced filtering utilities
 */
/**
 * Filter credentials by multiple types (OR logic)
 */
export declare function filterCredentialsByTypes(credentials: VerifiableCredential[], types: string[]): VerifiableCredential[];
/**
 * Filter credentials by multiple issuers
 */
export declare function filterCredentialsByIssuers(credentials: VerifiableCredential[], issuerURIs: URI[]): VerifiableCredential[];
/**
 * Filter credentials by subject ID
 */
export declare function filterCredentialsBySubject(credentials: VerifiableCredential[], subjectID: URI): VerifiableCredential[];
/**
 * Filter credentials by validity period
 */
export declare function filterCredentialsByValidity(credentials: VerifiableCredential[], options?: {
    validAt?: DateTime;
    includeExpired?: boolean;
    includeFuture?: boolean;
}): VerifiableCredential[];
/**
 * Advanced data transformation utilities
 */
/**
 * Convert credential to compact JSON (no formatting)
 */
export declare function credentialToCompactJSON(credential: VerifiableCredential): string;
/**
 * Convert multiple credentials to JSON array
 */
export declare function credentialsToJSON(credentials: VerifiableCredential[], indent?: number): string;
/**
 * Extract credential metadata
 */
export declare function extractCredentialMetadata(credential: VerifiableCredential): {
    id?: string;
    types: string[];
    issuer: string;
    issuanceDate?: string;
    expirationDate?: string;
    subjects: (string | undefined)[];
    isValid: boolean;
};
/**
 * Extract presentation metadata
 */
export declare function extractPresentationMetadata(presentation: VerifiablePresentation): {
    id?: string;
    types: string[];
    holder?: string;
    credentialCount: number;
    credentialTypes: string[];
};
/**
 * Credential sorting utilities
 */
/**
 * Sort credentials by issuance date
 */
export declare function sortCredentialsByIssuanceDate(credentials: VerifiableCredential[], ascending?: boolean): VerifiableCredential[];
/**
 * Sort credentials by expiration date
 */
export declare function sortCredentialsByExpirationDate(credentials: VerifiableCredential[], ascending?: boolean): VerifiableCredential[];
/**
 * Group credentials by type
 */
export declare function groupCredentialsByType(credentials: VerifiableCredential[]): Map<string, VerifiableCredential[]>;
/**
 * Group credentials by issuer
 */
export declare function groupCredentialsByIssuer(credentials: VerifiableCredential[]): Map<string, VerifiableCredential[]>;
/**
 * Validation and verification utilities
 */
/**
 * Basic structural validation for credentials
 */
export declare function validateCredentialStructure(credential: any): {
    valid: boolean;
    errors: string[];
};
/**
 * Basic structural validation for presentations
 */
export declare function validatePresentationStructure(presentation: any): {
    valid: boolean;
    errors: string[];
};
/**
 * Check if credential contains required fields for a specific type
 */
export declare function validateCredentialForType(credential: VerifiableCredential, requiredFields: string[]): {
    valid: boolean;
    missingFields: string[];
};
/**
 * Statistics and analysis utilities
 */
/**
 * Get credential statistics
 */
export declare function getCredentialStatistics(credentials: VerifiableCredential[]): {
    total: number;
    valid: number;
    expired: number;
    notYetValid: number;
    byType: Map<string, number>;
    byIssuer: Map<string, number>;
};
/**
 * Find duplicate credentials
 */
export declare function findDuplicateCredentials(credentials: VerifiableCredential[]): VerifiableCredential[][];
/**
 * Security and privacy utilities
 */
/**
 * Redact sensitive information from credential for logging
 */
export declare function redactCredentialForLogging(credential: VerifiableCredential): any;
/**
 * Generate credential fingerprint for deduplication
 */
export declare function generateCredentialFingerprint(credential: VerifiableCredential): string;
/**
 * Utility for working with credential contexts
 */
/**
 * Validate required contexts are present
 */
export declare function validateRequiredContexts(credential: VerifiableCredential, requiredContexts: string[]): {
    valid: boolean;
    missingContexts: string[];
};
/**
 * Export utilities for external systems
 */
/**
 * Convert credentials to CSV format (basic metadata)
 */
export declare function credentialsToCSV(credentials: VerifiableCredential[]): string;
/**
 * Create a summary report of credentials
 */
export declare function generateCredentialSummaryReport(credentials: VerifiableCredential[]): string;
//# sourceMappingURL=index.d.ts.map