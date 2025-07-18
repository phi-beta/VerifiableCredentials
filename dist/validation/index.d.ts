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
     * Validate RevocationList2020 status
     */
    private validateRevocationList2020Status;
    /**
     * Validate StatusList2021 entry
     */
    private validateStatusList2021Entry;
    /**
     * Validate required fields
     */
    private validateRequiredFields;
    /**
     * Check if object has nested property
     */
    private hasNestedProperty;
    /**
     * Extract public key from verification method
     * This is a simplified implementation - in production, this would resolve DIDs
     */
    private extractPublicKeyFromVerificationMethod;
    /**
     * Validate credential against multiple schemas
     */
    validateCredentialWithSchemas(credential: VerifiableCredential, schemaIds: string[]): Promise<ValidationResult>;
    /**
     * Validate credential subject data
     */
    validateCredentialSubject(credential: VerifiableCredential): ValidationResult;
    /**
     * Validate evidence
     */
    validateEvidence(credential: VerifiableCredential): ValidationResult;
    /**
     * Validate terms of use
     */
    validateTermsOfUse(termsOfUse: any[]): ValidationResult;
    /**
     * Validate refresh service
     */
    validateRefreshService(refreshService: any): ValidationResult;
    /**
     * Comprehensive validation with detailed reporting
     */
    validateWithDetailedReport(credential: VerifiableCredential, options?: ValidationOptions): Promise<{
        valid: boolean;
        errors: string[];
        warnings: string[];
        details: {
            context: ValidationResult;
            structure: ValidationResult;
            type: ValidationResult;
            issuer: ValidationResult;
            temporal: ValidationResult;
            proof: ValidationResult;
            schema: ValidationResult;
            revocation: ValidationResult;
            subject: ValidationResult;
            evidence: ValidationResult;
            termsOfUse: ValidationResult;
            refreshService: ValidationResult;
        };
    }>;
}
//# sourceMappingURL=index.d.ts.map