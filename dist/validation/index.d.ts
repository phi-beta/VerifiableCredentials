/**
 * Comprehensive validation algorithms for Verifiable Credentials
 * Implements W3C validation requirements and algorithms
 */
import { VerifiableCredential, VerifiablePresentation, ValidationResult } from '../types';
export interface ValidationOptions {
    validateSchema?: boolean;
    validateProof?: boolean;
    validateExpiration?: boolean;
    validateRevocation?: boolean;
    allowedTypes?: string[];
    trustedIssuers?: string[];
    requiredFields?: string[];
}
export declare class ValidationEngine {
    private contextManager;
    private securityManager;
    constructor();
    /**
     * Comprehensive credential validation
     */
    validateCredential(credential: VerifiableCredential, options?: ValidationOptions): Promise<ValidationResult>;
    /**
     * Comprehensive presentation validation
     */
    validatePresentation(presentation: VerifiablePresentation, options?: ValidationOptions): Promise<ValidationResult>;
    /**
     * Validate credential structure
     */
    private validateCredentialStructure;
    /**
     * Validate presentation structure
     */
    private validatePresentationStructure;
    /**
     * Validate credential type
     */
    private validateCredentialType;
    /**
     * Validate issuer
     */
    private validateIssuer;
    /**
     * Validate temporal constraints
     */
    private validateTemporalConstraints;
    /**
     * Validate credential proof
     */
    private validateCredentialProof;
    /**
     * Validate presentation proof
     */
    private validatePresentationProof;
    /**
     * Validate credential schema
     */
    private validateCredentialSchema;
    /**
     * Validate revocation status
     */
    private validateRevocationStatus;
    /**
     * Validate required fields
     */
    private validateRequiredFields;
    /**
     * Check if object has nested property
     */
    private hasNestedProperty;
}
//# sourceMappingURL=index.d.ts.map