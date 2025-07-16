/**
 * Verifier implementation for W3C Verifiable Credentials
 * Handles credential and presentation verification
 */
import { VerifiableCredential, VerifiablePresentation, ValidationResult } from '../types';
export interface VerifierOptions {
    id: string;
    name?: string;
    trustedIssuers?: string[];
    requiredProofPurposes?: string[];
}
export interface VerificationOptions {
    challenge?: string;
    domain?: string;
    checkRevocation?: boolean;
    checkExpiration?: boolean;
    trustedIssuers?: string[];
}
export declare class Verifier {
    private verifierId;
    private name?;
    private trustedIssuers;
    private requiredProofPurposes;
    private contextManager;
    private securityManager;
    constructor(options: VerifierOptions);
    /**
     * Verify a verifiable credential
     */
    verifyCredential(credential: VerifiableCredential, options?: VerificationOptions): Promise<ValidationResult>;
    /**
     * Verify a verifiable presentation
     */
    verifyPresentation(presentation: VerifiablePresentation, options?: VerificationOptions): Promise<ValidationResult>;
    /**
     * Validate credential structure
     */
    private validateCredentialStructure;
    /**
     * Validate presentation structure
     */
    private validatePresentationStructure;
    /**
     * Validate issuer
     */
    private validateIssuer;
    /**
     * Validate expiration
     */
    private validateExpiration;
    /**
     * Validate proof
     */
    private validateProof;
    /**
     * Validate presentation proof
     */
    private validatePresentationProof;
    /**
     * Check revocation status
     */
    private checkRevocationStatus;
    /**
     * Add trusted issuer
     */
    addTrustedIssuer(issuerUri: string): void;
    /**
     * Remove trusted issuer
     */
    removeTrustedIssuer(issuerUri: string): void;
    /**
     * Get trusted issuers
     */
    getTrustedIssuers(): string[];
    /**
     * Get verifier information
     */
    getVerifierInfo(): {
        id: string;
        name?: string;
    };
}
//# sourceMappingURL=verifier.d.ts.map