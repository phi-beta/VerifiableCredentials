"use strict";
/**
 * Utility functions for Verifiable Credentials
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateURI = generateURI;
exports.getCurrentDateTime = getCurrentDateTime;
exports.isValidURI = isValidURI;
exports.isValidDateTime = isValidDateTime;
exports.getIssuerURI = getIssuerURI;
exports.getHolderURI = getHolderURI;
exports.getSubjectIDs = getSubjectIDs;
exports.hasCredentialType = hasCredentialType;
exports.hasPresentationType = hasPresentationType;
exports.isCredentialValid = isCredentialValid;
exports.getCredentialsFromPresentation = getCredentialsFromPresentation;
exports.filterCredentialsByType = filterCredentialsByType;
exports.filterCredentialsByIssuer = filterCredentialsByIssuer;
exports.filterValidCredentials = filterValidCredentials;
exports.deepClone = deepClone;
exports.mergeContexts = mergeContexts;
exports.normalizeTypes = normalizeTypes;
exports.arraysEqual = arraysEqual;
exports.sanitizeIdentifier = sanitizeIdentifier;
exports.simpleHash = simpleHash;
exports.credentialToJSON = credentialToJSON;
exports.presentationToJSON = presentationToJSON;
exports.parseCredentialFromJSON = parseCredentialFromJSON;
exports.parsePresentationFromJSON = parsePresentationFromJSON;
/**
 * Generate a unique URI for credentials or presentations
 */
function generateURI(prefix = 'urn:uuid') {
    const uuid = require('uuid').v4();
    return `${prefix}:${uuid}`;
}
/**
 * Get current ISO 8601 datetime string
 */
function getCurrentDateTime() {
    return new Date().toISOString();
}
/**
 * Check if a string is a valid URI
 */
function isValidURI(uri) {
    try {
        new URL(uri);
        return true;
    }
    catch {
        // Check for URN format
        return /^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%\/?#]+$/i.test(uri);
    }
}
/**
 * Check if a string is a valid ISO 8601 datetime
 */
function isValidDateTime(dateTime) {
    try {
        const date = new Date(dateTime);
        return !isNaN(date.getTime()) && dateTime === date.toISOString();
    }
    catch {
        return false;
    }
}
/**
 * Extract issuer URI from credential
 */
function getIssuerURI(credential) {
    return typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
}
/**
 * Extract holder URI from presentation
 */
function getHolderURI(presentation) {
    return presentation.holder;
}
/**
 * Get all subject IDs from a credential
 */
function getSubjectIDs(credential) {
    const subjects = Array.isArray(credential.credentialSubject)
        ? credential.credentialSubject
        : [credential.credentialSubject];
    return subjects.map(subject => subject.id);
}
/**
 * Check if credential has a specific type
 */
function hasCredentialType(credential, type) {
    const types = Array.isArray(credential.type) ? credential.type : [credential.type];
    return types.includes(type);
}
/**
 * Check if presentation has a specific type
 */
function hasPresentationType(presentation, type) {
    const types = Array.isArray(presentation.type) ? presentation.type : [presentation.type];
    return types.includes(type);
}
/**
 * Check if credential is currently valid (not expired)
 */
function isCredentialValid(credential) {
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
function getCredentialsFromPresentation(presentation) {
    return presentation.verifiableCredential || [];
}
/**
 * Filter credentials by type
 */
function filterCredentialsByType(credentials, type) {
    return credentials.filter(credential => hasCredentialType(credential, type));
}
/**
 * Filter credentials by issuer
 */
function filterCredentialsByIssuer(credentials, issuerURI) {
    return credentials.filter(credential => getIssuerURI(credential) === issuerURI);
}
/**
 * Filter valid (non-expired) credentials
 */
function filterValidCredentials(credentials) {
    return credentials.filter(credential => isCredentialValid(credential));
}
/**
 * Deep clone an object
 */
function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}
/**
 * Merge contexts from multiple sources
 */
function mergeContexts(...contexts) {
    const result = [];
    const seen = new Set();
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
function normalizeTypes(types) {
    return Array.isArray(types) ? types : [types];
}
/**
 * Check if two arrays have the same elements (order independent)
 */
function arraysEqual(a, b) {
    if (a.length !== b.length)
        return false;
    const sortedA = [...a].sort();
    const sortedB = [...b].sort();
    return sortedA.every((val, index) => val === sortedB[index]);
}
/**
 * Sanitize a string for use as an identifier
 */
function sanitizeIdentifier(str) {
    return str.replace(/[^a-zA-Z0-9-_]/g, '_');
}
/**
 * Create a simple hash of a string
 */
function simpleHash(str) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(str).digest('hex').substring(0, 16);
}
/**
 * Convert credential to JSON string with proper formatting
 */
function credentialToJSON(credential, indent = 2) {
    return JSON.stringify(credential, null, indent);
}
/**
 * Convert presentation to JSON string with proper formatting
 */
function presentationToJSON(presentation, indent = 2) {
    return JSON.stringify(presentation, null, indent);
}
/**
 * Parse JSON string to credential with validation
 */
function parseCredentialFromJSON(json) {
    try {
        const parsed = JSON.parse(json);
        if (!parsed || typeof parsed !== 'object') {
            throw new Error('Invalid JSON format');
        }
        return parsed;
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to parse credential JSON: ${errorMessage}`);
    }
}
/**
 * Parse JSON string to presentation with validation
 */
function parsePresentationFromJSON(json) {
    try {
        const parsed = JSON.parse(json);
        if (!parsed || typeof parsed !== 'object') {
            throw new Error('Invalid JSON format');
        }
        return parsed;
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to parse presentation JSON: ${errorMessage}`);
    }
}
//# sourceMappingURL=index.js.map