/**
 * Utility functions for Verifiable Credentials
 */

import { VerifiableCredential, VerifiablePresentation, URI, DateTime } from '../types';

/**
 * Generate a unique URI for credentials or presentations
 */
export function generateURI(prefix: string = 'urn:uuid'): URI {
  const uuid = require('uuid').v4();
  return `${prefix}:${uuid}`;
}

/**
 * Get current ISO 8601 datetime string
 */
export function getCurrentDateTime(): DateTime {
  return new Date().toISOString();
}

/**
 * Check if a string is a valid URI
 */
export function isValidURI(uri: string): boolean {
  try {
    new URL(uri);
    return true;
  } catch {
    // Check for URN format
    return /^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%\/?#]+$/i.test(uri);
  }
}

/**
 * Check if a string is a valid ISO 8601 datetime
 */
export function isValidDateTime(dateTime: string): boolean {
  try {
    const date = new Date(dateTime);
    return !isNaN(date.getTime()) && dateTime === date.toISOString();
  } catch {
    return false;
  }
}

/**
 * Extract issuer URI from credential
 */
export function getIssuerURI(credential: VerifiableCredential): URI {
  return typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
}

/**
 * Extract holder URI from presentation
 */
export function getHolderURI(presentation: VerifiablePresentation): URI | undefined {
  return presentation.holder;
}

/**
 * Get all subject IDs from a credential
 */
export function getSubjectIDs(credential: VerifiableCredential): (URI | undefined)[] {
  const subjects = Array.isArray(credential.credentialSubject) 
    ? credential.credentialSubject 
    : [credential.credentialSubject];
  
  return subjects.map(subject => subject.id);
}

/**
 * Check if credential has a specific type
 */
export function hasCredentialType(credential: VerifiableCredential, type: string): boolean {
  const types = Array.isArray(credential.type) ? credential.type : [credential.type];
  return types.includes(type);
}

/**
 * Check if presentation has a specific type
 */
export function hasPresentationType(presentation: VerifiablePresentation, type: string): boolean {
  const types = Array.isArray(presentation.type) ? presentation.type : [presentation.type];
  return types.includes(type);
}

/**
 * Check if credential is currently valid (not expired)
 */
export function isCredentialValid(credential: VerifiableCredential): boolean {
  const now = new Date();
  
  // Check validFrom
  if (credential.validFrom) {
    const validFrom = new Date(credential.validFrom);
    if (now < validFrom) {
      return false;
    }
  }
  
  // Check validUntil
  if (credential.validUntil) {
    const validUntil = new Date(credential.validUntil);
    if (now > validUntil) {
      return false;
    }
  }
  
  return true;
}

/**
 * Get credentials from presentation
 */
export function getCredentialsFromPresentation(presentation: VerifiablePresentation): VerifiableCredential[] {
  return presentation.verifiableCredential || [];
}

/**
 * Filter credentials by type
 */
export function filterCredentialsByType(credentials: VerifiableCredential[], type: string): VerifiableCredential[] {
  return credentials.filter(credential => hasCredentialType(credential, type));
}

/**
 * Filter credentials by issuer
 */
export function filterCredentialsByIssuer(credentials: VerifiableCredential[], issuerURI: URI): VerifiableCredential[] {
  return credentials.filter(credential => getIssuerURI(credential) === issuerURI);
}

/**
 * Filter valid (non-expired) credentials
 */
export function filterValidCredentials(credentials: VerifiableCredential[]): VerifiableCredential[] {
  return credentials.filter(credential => isCredentialValid(credential));
}

/**
 * Deep clone an object
 */
export function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Merge contexts from multiple sources
 */
export function mergeContexts(...contexts: (string | string[])[]): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  
  for (const context of contexts) {
    const contextArray = Array.isArray(context) ? context : [context];
    for (const ctx of contextArray) {
      if (!seen.has(ctx)) {
        seen.add(ctx);
        result.push(ctx);
      }
    }
  }
  
  return result;
}

/**
 * Normalize types to always be an array
 */
export function normalizeTypes(types: string | string[]): string[] {
  return Array.isArray(types) ? types : [types];
}

/**
 * Check if two arrays have the same elements (order independent)
 */
export function arraysEqual<T>(a: T[], b: T[]): boolean {
  if (a.length !== b.length) return false;
  
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  
  return sortedA.every((val, index) => val === sortedB[index]);
}

/**
 * Sanitize a string for use as an identifier
 */
export function sanitizeIdentifier(str: string): string {
  return str.replace(/[^a-zA-Z0-9-_]/g, '_');
}

/**
 * Create a simple hash of a string
 */
export function simpleHash(str: string): string {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(str).digest('hex').substring(0, 16);
}

/**
 * Convert credential to JSON string with proper formatting
 */
export function credentialToJSON(credential: VerifiableCredential, indent: number = 2): string {
  return JSON.stringify(credential, null, indent);
}

/**
 * Convert presentation to JSON string with proper formatting
 */
export function presentationToJSON(presentation: VerifiablePresentation, indent: number = 2): string {
  return JSON.stringify(presentation, null, indent);
}

/**
 * Parse JSON string to credential with validation
 */
export function parseCredentialFromJSON(json: string): VerifiableCredential {
  try {
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid JSON format');
    }
    return parsed as VerifiableCredential;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to parse credential JSON: ${errorMessage}`);
  }
}

/**
 * Parse JSON string to presentation with validation
 */
export function parsePresentationFromJSON(json: string): VerifiablePresentation {
  try {
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid JSON format');
    }
    return parsed as VerifiablePresentation;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Failed to parse presentation JSON: ${errorMessage}`);
  }
}

/**
 * Advanced date/time utilities
 */

/**
 * Add time duration to a date
 */
export function addDuration(dateTime: DateTime, duration: { years?: number; months?: number; days?: number; hours?: number; minutes?: number }): DateTime {
  const date = new Date(dateTime);
  
  if (duration.years) date.setFullYear(date.getFullYear() + duration.years);
  if (duration.months) date.setMonth(date.getMonth() + duration.months);
  if (duration.days) date.setDate(date.getDate() + duration.days);
  if (duration.hours) date.setHours(date.getHours() + duration.hours);
  if (duration.minutes) date.setMinutes(date.getMinutes() + duration.minutes);
  
  return date.toISOString();
}

/**
 * Check if a date is expired
 */
export function isExpired(expirationDate: DateTime): boolean {
  return new Date() > new Date(expirationDate);
}

/**
 * Check if a date is in the future (not yet valid)
 */
export function isFuture(validFromDate: DateTime): boolean {
  return new Date() < new Date(validFromDate);
}

/**
 * Get time until expiration in milliseconds
 */
export function getTimeUntilExpiration(expirationDate: DateTime): number {
  return new Date(expirationDate).getTime() - new Date().getTime();
}

/**
 * Format duration in human readable format
 */
export function formatDuration(milliseconds: number): string {
  const days = Math.floor(milliseconds / (1000 * 60 * 60 * 24));
  const hours = Math.floor((milliseconds % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((milliseconds % (1000 * 60 * 60)) / (1000 * 60));
  
  if (days > 0) return `${days} days, ${hours} hours`;
  if (hours > 0) return `${hours} hours, ${minutes} minutes`;
  return `${minutes} minutes`;
}

/**
 * Advanced URI utilities
 */

/**
 * Generate a DID-style URI
 */
export function generateDID(method: string = 'web', identifier?: string): URI {
  const id = identifier || require('uuid').v4();
  return `did:${method}:${id}`;
}

/**
 * Parse DID components
 */
export function parseDID(did: string): { method: string; identifier: string; path?: string; query?: string; fragment?: string } | null {
  const didRegex = /^did:([a-z0-9]+):([a-zA-Z0-9._:-]+)(?:\/([^?#]*))?(?:\?([^#]*))?(?:#(.*))?$/;
  const match = did.match(didRegex);
  
  if (!match) return null;
  
  return {
    method: match[1],
    identifier: match[2],
    path: match[3],
    query: match[4],
    fragment: match[5]
  };
}

/**
 * Generate a credential ID with prefix
 */
export function generateCredentialID(issuerDomain: string): URI {
  const uuid = require('uuid').v4();
  return `https://${issuerDomain}/credentials/${uuid}`;
}

/**
 * Generate a presentation ID
 */
export function generatePresentationID(holderDomain?: string): URI {
  const uuid = require('uuid').v4();
  if (holderDomain) {
    return `https://${holderDomain}/presentations/${uuid}`;
  }
  return `urn:uuid:${uuid}`;
}

/**
 * Advanced filtering utilities
 */

/**
 * Filter credentials by multiple types (OR logic)
 */
export function filterCredentialsByTypes(credentials: VerifiableCredential[], types: string[]): VerifiableCredential[] {
  return credentials.filter(credential => 
    types.some(type => hasCredentialType(credential, type))
  );
}

/**
 * Filter credentials by multiple issuers
 */
export function filterCredentialsByIssuers(credentials: VerifiableCredential[], issuerURIs: URI[]): VerifiableCredential[] {
  return credentials.filter(credential => 
    issuerURIs.includes(getIssuerURI(credential))
  );
}

/**
 * Filter credentials by subject ID
 */
export function filterCredentialsBySubject(credentials: VerifiableCredential[], subjectID: URI): VerifiableCredential[] {
  return credentials.filter(credential => {
    const subjectIDs = getSubjectIDs(credential);
    return subjectIDs.includes(subjectID);
  });
}

/**
 * Filter credentials by validity period
 */
export function filterCredentialsByValidity(
  credentials: VerifiableCredential[], 
  options: { 
    validAt?: DateTime; 
    includeExpired?: boolean; 
    includeFuture?: boolean 
  } = {}
): VerifiableCredential[] {
  const checkDate = options.validAt ? new Date(options.validAt) : new Date();
  
  return credentials.filter(credential => {
    // Check validFrom
    if (credential.validFrom) {
      const validFrom = new Date(credential.validFrom);
      if (checkDate < validFrom && !options.includeFuture) {
        return false;
      }
    }
    
    // Check validUntil
    if (credential.validUntil) {
      const validUntil = new Date(credential.validUntil);
      if (checkDate > validUntil && !options.includeExpired) {
        return false;
      }
    }
    
    return true;
  });
}

/**
 * Advanced data transformation utilities
 */

/**
 * Convert credential to compact JSON (no formatting)
 */
export function credentialToCompactJSON(credential: VerifiableCredential): string {
  return JSON.stringify(credential);
}

/**
 * Convert multiple credentials to JSON array
 */
export function credentialsToJSON(credentials: VerifiableCredential[], indent: number = 2): string {
  return JSON.stringify(credentials, null, indent);
}

/**
 * Extract credential metadata
 */
export function extractCredentialMetadata(credential: VerifiableCredential): {
  id?: string;
  types: string[];
  issuer: string;
  issuanceDate?: string;
  expirationDate?: string;
  subjects: (string | undefined)[];
  isValid: boolean;
} {
  return {
    id: credential.id,
    types: normalizeTypes(credential.type),
    issuer: getIssuerURI(credential),
    issuanceDate: credential.validFrom,
    expirationDate: credential.validUntil,
    subjects: getSubjectIDs(credential),
    isValid: isCredentialValid(credential)
  };
}

/**
 * Extract presentation metadata
 */
export function extractPresentationMetadata(presentation: VerifiablePresentation): {
  id?: string;
  types: string[];
  holder?: string;
  credentialCount: number;
  credentialTypes: string[];
} {
  const credentials = getCredentialsFromPresentation(presentation);
  const allTypes = new Set<string>();
  
  credentials.forEach(cred => {
    normalizeTypes(cred.type).forEach(type => allTypes.add(type));
  });
  
  return {
    id: presentation.id,
    types: normalizeTypes(presentation.type),
    holder: getHolderURI(presentation),
    credentialCount: credentials.length,
    credentialTypes: Array.from(allTypes)
  };
}

/**
 * Credential sorting utilities
 */

/**
 * Sort credentials by issuance date
 */
export function sortCredentialsByIssuanceDate(credentials: VerifiableCredential[], ascending: boolean = true): VerifiableCredential[] {
  return [...credentials].sort((a, b) => {
    const dateA = new Date(a.validFrom || 0);
    const dateB = new Date(b.validFrom || 0);
    return ascending ? dateA.getTime() - dateB.getTime() : dateB.getTime() - dateA.getTime();
  });
}

/**
 * Sort credentials by expiration date
 */
export function sortCredentialsByExpirationDate(credentials: VerifiableCredential[], ascending: boolean = true): VerifiableCredential[] {
  return [...credentials].sort((a, b) => {
    const dateA = new Date(a.validUntil || '9999-12-31T23:59:59Z');
    const dateB = new Date(b.validUntil || '9999-12-31T23:59:59Z');
    return ascending ? dateA.getTime() - dateB.getTime() : dateB.getTime() - dateA.getTime();
  });
}

/**
 * Group credentials by type
 */
export function groupCredentialsByType(credentials: VerifiableCredential[]): Map<string, VerifiableCredential[]> {
  const groups = new Map<string, VerifiableCredential[]>();
  
  credentials.forEach(credential => {
    const types = normalizeTypes(credential.type);
    types.forEach(type => {
      if (!groups.has(type)) {
        groups.set(type, []);
      }
      groups.get(type)!.push(credential);
    });
  });
  
  return groups;
}

/**
 * Group credentials by issuer
 */
export function groupCredentialsByIssuer(credentials: VerifiableCredential[]): Map<string, VerifiableCredential[]> {
  const groups = new Map<string, VerifiableCredential[]>();
  
  credentials.forEach(credential => {
    const issuer = getIssuerURI(credential);
    if (!groups.has(issuer)) {
      groups.set(issuer, []);
    }
    groups.get(issuer)!.push(credential);
  });
  
  return groups;
}

/**
 * Validation and verification utilities
 */

/**
 * Basic structural validation for credentials
 */
export function validateCredentialStructure(credential: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!credential) {
    errors.push('Credential is null or undefined');
    return { valid: false, errors };
  }
  
  if (!credential['@context']) {
    errors.push('Missing @context field');
  }
  
  if (!credential.type) {
    errors.push('Missing type field');
  } else {
    const types = normalizeTypes(credential.type);
    if (!types.includes('VerifiableCredential')) {
      errors.push('Type must include VerifiableCredential');
    }
  }
  
  if (!credential.issuer) {
    errors.push('Missing issuer field');
  }
  
  if (!credential.credentialSubject) {
    errors.push('Missing credentialSubject field');
  }
  
  return { valid: errors.length === 0, errors };
}

/**
 * Basic structural validation for presentations
 */
export function validatePresentationStructure(presentation: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!presentation) {
    errors.push('Presentation is null or undefined');
    return { valid: false, errors };
  }
  
  if (!presentation['@context']) {
    errors.push('Missing @context field');
  }
  
  if (!presentation.type) {
    errors.push('Missing type field');
  } else {
    const types = normalizeTypes(presentation.type);
    if (!types.includes('VerifiablePresentation')) {
      errors.push('Type must include VerifiablePresentation');
    }
  }
  
  if (!presentation.verifiableCredential || !Array.isArray(presentation.verifiableCredential)) {
    errors.push('Missing or invalid verifiableCredential field');
  }
  
  return { valid: errors.length === 0, errors };
}

/**
 * Check if credential contains required fields for a specific type
 */
export function validateCredentialForType(credential: VerifiableCredential, requiredFields: string[]): { valid: boolean; missingFields: string[] } {
  const missingFields: string[] = [];
  const credentialSubject = credential.credentialSubject;
  
  if (!credentialSubject) {
    return { valid: false, missingFields: requiredFields };
  }
  
  const subject = Array.isArray(credentialSubject) ? credentialSubject[0] : credentialSubject;
  
  requiredFields.forEach(field => {
    if (!(field in subject)) {
      missingFields.push(field);
    }
  });
  
  return { valid: missingFields.length === 0, missingFields };
}

/**
 * Statistics and analysis utilities
 */

/**
 * Get credential statistics
 */
export function getCredentialStatistics(credentials: VerifiableCredential[]): {
  total: number;
  valid: number;
  expired: number;
  notYetValid: number;
  byType: Map<string, number>;
  byIssuer: Map<string, number>;
} {
  const stats = {
    total: credentials.length,
    valid: 0,
    expired: 0,
    notYetValid: 0,
    byType: new Map<string, number>(),
    byIssuer: new Map<string, number>()
  };
  
  credentials.forEach(credential => {
    // Validity statistics
    if (isCredentialValid(credential)) {
      stats.valid++;
    } else {
      if (credential.validUntil && isExpired(credential.validUntil)) {
        stats.expired++;
      }
      if (credential.validFrom && isFuture(credential.validFrom)) {
        stats.notYetValid++;
      }
    }
    
    // Type statistics
    const types = normalizeTypes(credential.type);
    types.forEach(type => {
      stats.byType.set(type, (stats.byType.get(type) || 0) + 1);
    });
    
    // Issuer statistics
    const issuer = getIssuerURI(credential);
    stats.byIssuer.set(issuer, (stats.byIssuer.get(issuer) || 0) + 1);
  });
  
  return stats;
}

/**
 * Find duplicate credentials
 */
export function findDuplicateCredentials(credentials: VerifiableCredential[]): VerifiableCredential[][] {
  const groups: Map<string, VerifiableCredential[]> = new Map();
  
  credentials.forEach(credential => {
    const key = credential.id || credentialToCompactJSON(credential);
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(credential);
  });
  
  return Array.from(groups.values()).filter(group => group.length > 1);
}

/**
 * Security and privacy utilities
 */

/**
 * Redact sensitive information from credential for logging
 */
export function redactCredentialForLogging(credential: VerifiableCredential): any {
  const redacted = deepClone(credential);
  
  // Redact proof
  if (redacted.proof) {
    if (Array.isArray(redacted.proof)) {
      redacted.proof = redacted.proof.map(p => ({ ...p, proofValue: '[REDACTED]' }));
    } else {
      redacted.proof = { ...redacted.proof, proofValue: '[REDACTED]' };
    }
  }
  
  // Redact sensitive subject fields (basic approach)
  if (redacted.credentialSubject) {
    const subject = Array.isArray(redacted.credentialSubject) 
      ? redacted.credentialSubject[0] 
      : redacted.credentialSubject;
    
    // Common sensitive fields to redact
    const sensitiveFields = ['ssn', 'socialSecurityNumber', 'passportNumber', 'driverLicenseNumber', 'birthDate'];
    sensitiveFields.forEach(field => {
      if (field in subject) {
        subject[field] = '[REDACTED]';
      }
    });
  }
  
  return redacted;
}

/**
 * Generate credential fingerprint for deduplication
 */
export function generateCredentialFingerprint(credential: VerifiableCredential): string {
  // Create a normalized version without proof and id for fingerprinting
  const normalized = deepClone(credential);
  delete normalized.id;
  delete normalized.proof;
  delete normalized.validFrom; // Exclude issuance date for content-based dedup
  
  return simpleHash(JSON.stringify(normalized));
}

/**
 * Utility for working with credential contexts
 */

/**
 * Validate required contexts are present
 */
export function validateRequiredContexts(credential: VerifiableCredential, requiredContexts: string[]): { valid: boolean; missingContexts: string[] } {
  const contexts = Array.isArray(credential['@context']) ? credential['@context'] : [credential['@context']];
  const missingContexts = requiredContexts.filter(required => !contexts.includes(required));
  
  return {
    valid: missingContexts.length === 0,
    missingContexts
  };
}

/**
 * Export utilities for external systems
 */

/**
 * Convert credentials to CSV format (basic metadata)
 */
export function credentialsToCSV(credentials: VerifiableCredential[]): string {
  const headers = ['ID', 'Type', 'Issuer', 'Subject', 'IssuanceDate', 'ExpirationDate', 'IsValid'];
  const rows = [headers.join(',')];
  
  credentials.forEach(credential => {
    const metadata = extractCredentialMetadata(credential);
    const types = metadata.types.filter(t => t !== 'VerifiableCredential').join(';');
    const subjects = metadata.subjects.filter(s => s).join(';');
    
    const row = [
      metadata.id || '',
      types,
      metadata.issuer,
      subjects,
      metadata.issuanceDate || '',
      metadata.expirationDate || '',
      metadata.isValid.toString()
    ];
    
    rows.push(row.map(field => `"${field}"`).join(','));
  });
  
  return rows.join('\n');
}

/**
 * Create a summary report of credentials
 */
export function generateCredentialSummaryReport(credentials: VerifiableCredential[]): string {
  const stats = getCredentialStatistics(credentials);
  const duplicates = findDuplicateCredentials(credentials);
  
  let report = '=== Credential Summary Report ===\n\n';
  report += `Total Credentials: ${stats.total}\n`;
  report += `Valid Credentials: ${stats.valid}\n`;
  report += `Expired Credentials: ${stats.expired}\n`;
  report += `Not Yet Valid: ${stats.notYetValid}\n`;
  report += `Duplicate Credentials: ${duplicates.length}\n\n`;
  
  report += '=== Credentials by Type ===\n';
  Array.from(stats.byType.entries())
    .sort((a, b) => b[1] - a[1])
    .forEach(([type, count]) => {
      report += `${type}: ${count}\n`;
    });
  
  report += '\n=== Credentials by Issuer ===\n';
  Array.from(stats.byIssuer.entries())
    .sort((a, b) => b[1] - a[1])
    .forEach(([issuer, count]) => {
      report += `${issuer}: ${count}\n`;
    });
  
  return report;
}
