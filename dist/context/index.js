"use strict";
/**
 * JSON-LD Context handling for Verifiable Credentials
 * Manages context loading, validation, and term expansion
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContextManager = exports.W3C_DID_CONTEXT = exports.W3C_VC_CONTEXT_V1 = exports.W3C_VC_CONTEXT_V2 = void 0;
const jsonld = __importStar(require("jsonld"));
// Standard W3C contexts
exports.W3C_VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';
exports.W3C_VC_CONTEXT_V1 = 'https://www.w3.org/2018/credentials/v1';
exports.W3C_DID_CONTEXT = 'https://www.w3.org/ns/did/v1';
// Built-in contexts for offline operation
const BUILT_IN_CONTEXTS = {
    [exports.W3C_VC_CONTEXT_V2]: {
        '@version': 2,
        '@protected': true,
        'id': '@id',
        'type': '@type',
        'VerifiableCredential': {
            '@id': 'https://www.w3.org/2018/credentials#VerifiableCredential',
            '@context': {
                '@version': 2,
                '@protected': true,
                'id': '@id',
                'type': '@type',
                'credentialSubject': {
                    '@id': 'https://www.w3.org/2018/credentials#credentialSubject',
                    '@type': '@id'
                },
                'issuer': {
                    '@id': 'https://www.w3.org/2018/credentials#issuer',
                    '@type': '@id'
                },
                'validFrom': {
                    '@id': 'https://www.w3.org/2018/credentials#validFrom',
                    '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
                },
                'validUntil': {
                    '@id': 'https://www.w3.org/2018/credentials#validUntil',
                    '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
                },
                'proof': {
                    '@id': 'https://w3id.org/security#proof',
                    '@type': '@id',
                    '@container': '@graph'
                }
            }
        },
        'VerifiablePresentation': {
            '@id': 'https://www.w3.org/2018/credentials#VerifiablePresentation',
            '@context': {
                '@version': 2,
                '@protected': true,
                'id': '@id',
                'type': '@type',
                'verifiableCredential': {
                    '@id': 'https://www.w3.org/2018/credentials#verifiableCredential',
                    '@type': '@id',
                    '@container': '@graph'
                },
                'holder': {
                    '@id': 'https://www.w3.org/2018/credentials#holder',
                    '@type': '@id'
                }
            }
        }
    },
    [exports.W3C_DID_CONTEXT]: {
        '@version': 1.1,
        '@protected': true,
        'id': '@id',
        'type': '@type',
        'verificationMethod': {
            '@id': 'https://w3id.org/security#verificationMethod',
            '@type': '@id'
        },
        'authentication': {
            '@id': 'https://w3id.org/security#authenticationMethod',
            '@type': '@id',
            '@container': '@set'
        },
        'assertionMethod': {
            '@id': 'https://w3id.org/security#assertionMethod',
            '@type': '@id',
            '@container': '@set'
        }
    }
};
class ContextManager {
    constructor() {
        this.customContexts = new Map();
    }
    /**
     * Add a custom context
     */
    addContext(url, context) {
        this.customContexts.set(url, context);
    }
    /**
     * Get a context by URL
     */
    getContext(url) {
        if (BUILT_IN_CONTEXTS[url]) {
            return BUILT_IN_CONTEXTS[url];
        }
        return this.customContexts.get(url);
    }
    /**
     * Expand a JSON-LD document (simplified version)
     */
    async expand(document) {
        try {
            // For now, use basic expansion without custom document loader
            return await jsonld.expand(document);
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to expand document: ${errorMessage}`);
        }
    }
    /**
     * Compact a JSON-LD document (simplified version)
     */
    async compact(document, context) {
        try {
            return await jsonld.compact(document, context);
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to compact document: ${errorMessage}`);
        }
    }
    /**
     * Normalize a JSON-LD document (canonicalization)
     */
    async normalize(document) {
        try {
            return await jsonld.normalize(document, {
                algorithm: 'URDNA2015',
                format: 'application/n-quads'
            });
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to normalize document: ${errorMessage}`);
        }
    }
    /**
     * Validate context usage in a document
     */
    async validateContext(document) {
        const errors = [];
        const warnings = [];
        try {
            // Check if @context is present
            if (!document['@context']) {
                errors.push('Missing @context property');
                return { valid: false, errors, warnings };
            }
            // Check for required contexts based on document type
            const contexts = Array.isArray(document['@context'])
                ? document['@context']
                : [document['@context']];
            const types = Array.isArray(document.type) ? document.type : [document.type];
            if (types.includes('VerifiableCredential') || types.includes('VerifiablePresentation')) {
                const hasVcContext = contexts.some(ctx => ctx === exports.W3C_VC_CONTEXT_V2 || ctx === exports.W3C_VC_CONTEXT_V1);
                if (!hasVcContext) {
                    errors.push('Missing required W3C Verifiable Credentials context');
                }
            }
            // Try to expand the document to validate contexts
            await this.expand(document);
            return { valid: errors.length === 0, errors, warnings };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Context validation failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
    /**
     * Check if a context is available
     */
    hasContext(url) {
        return !!(BUILT_IN_CONTEXTS[url] || this.customContexts.has(url));
    }
}
exports.ContextManager = ContextManager;
//# sourceMappingURL=index.js.map