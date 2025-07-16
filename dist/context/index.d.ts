/**
 * JSON-LD Context handling for Verifiable Credentials
 * Manages context loading, validation, and term expansion
 */
import { ValidationResult } from '../types';
export declare const W3C_VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
export declare const W3C_VC_CONTEXT_V1 = "https://www.w3.org/2018/credentials/v1";
export declare const W3C_DID_CONTEXT = "https://www.w3.org/ns/did/v1";
export declare class ContextManager {
    private customContexts;
    /**
     * Add a custom context
     */
    addContext(url: string, context: any): void;
    /**
     * Get a context by URL
     */
    getContext(url: string): any;
    /**
     * Expand a JSON-LD document (simplified version)
     */
    expand(document: any): Promise<any>;
    /**
     * Compact a JSON-LD document (simplified version)
     */
    compact(document: any, context: any): Promise<any>;
    /**
     * Normalize a JSON-LD document (canonicalization)
     */
    normalize(document: any): Promise<string>;
    /**
     * Validate context usage in a document
     */
    validateContext(document: any): Promise<ValidationResult>;
    /**
     * Check if a context is available
     */
    hasContext(url: string): boolean;
}
//# sourceMappingURL=index.d.ts.map