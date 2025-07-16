/**
 * Holder implementation for W3C Verifiable Credentials
 * Handles credential storage, presentation creation, and selective disclosure
 */
import { VerifiableCredential, VerifiablePresentation } from '../types';
export interface HolderOptions {
    id: string;
    name?: string;
    keyPair?: any;
}
export interface PresentationOptions {
    verifiableCredential?: VerifiableCredential[];
    type?: string | string[];
    context?: string | string[];
    id?: string;
    holder?: string;
    challenge?: string;
    domain?: string;
    termsOfUse?: any[];
}
export declare class Holder {
    private holderId;
    private name?;
    private credentials;
    private securityManager;
    constructor(options: HolderOptions);
    /**
     * Store a verifiable credential
     */
    storeCredential(credential: VerifiableCredential): void;
    /**
     * Retrieve a stored credential by ID
     */
    getCredential(credentialId: string): VerifiableCredential | undefined;
    /**
     * List all stored credentials
     */
    listCredentials(): VerifiableCredential[];
    /**
     * Remove a credential from storage
     */
    removeCredential(credentialId: string): boolean;
    /**
     * Create a verifiable presentation
     */
    createPresentation(options: PresentationOptions): Promise<VerifiablePresentation>;
    /**
     * Sign a presentation with the holder's private key
     */
    private signPresentation;
    /**
     * Create a presentation from specific credentials
     */
    createPresentationFromCredentials(credentialIds: string[], options?: Omit<PresentationOptions, 'verifiableCredential'>): Promise<VerifiablePresentation>;
    /**
     * Filter credentials by type
     */
    getCredentialsByType(type: string): VerifiableCredential[];
    /**
     * Filter credentials by issuer
     */
    getCredentialsByIssuer(issuerUri: string): VerifiableCredential[];
    /**
     * Check if a credential is expired
     */
    isCredentialExpired(credential: VerifiableCredential): boolean;
    /**
     * Get valid (non-expired) credentials
     */
    getValidCredentials(): VerifiableCredential[];
    /**
     * Get expired credentials
     */
    getExpiredCredentials(): VerifiableCredential[];
    /**
     * Get holder information
     */
    getHolderInfo(): {
        id: string;
        name?: string;
    };
    /**
     * Update holder information
     */
    updateHolderInfo(updates: {
        name?: string;
    }): void;
    /**
     * Export credentials as JSON
     */
    exportCredentials(): string;
    /**
     * Import credentials from JSON
     */
    importCredentials(credentialsJson: string): void;
}
//# sourceMappingURL=holder.d.ts.map