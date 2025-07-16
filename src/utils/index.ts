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
