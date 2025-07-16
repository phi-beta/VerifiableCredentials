/**
 * Issuer implementation for W3C Verifiable Credentials
 * Handles credential issuance and signing
 */
import { VerifiableCredential, Issuer as IssuerType, CredentialSubject } from '../types';
export interface IssuerOptions {
    id: string;
    name?: string;
    description?: string;
    url?: string;
    image?: string;
    keyPair?: any;
}
export declare class Issuer {
    private issuerInfo;
    private securityManager;
    constructor(options: IssuerOptions);
    /**
     * Issue a new verifiable credential
     */
    issueCredential(options: {
        credentialSubject: CredentialSubject | CredentialSubject[];
        type?: string | string[];
        validFrom?: string;
        validUntil?: string;
        context?: string | string[];
        id?: string;
        credentialStatus?: any;
        credentialSchema?: any;
        evidence?: any[];
        refreshService?: any;
        termsOfUse?: any[];
    }): Promise<VerifiableCredential>;
    /**
     * Sign a credential with the issuer's private key
     */
    private signCredential;
    /**
     * Revoke a credential (update its status)
     */
    revokeCredential(credentialId: string, reason?: string): Promise<void>;
    /**
     * Get issuer information
     */
    getIssuerInfo(): IssuerType;
    /**
     * Update issuer information
     */
    updateIssuerInfo(updates: Partial<IssuerOptions>): void;
    /**
     * Batch issue multiple credentials
     */
    batchIssueCredentials(credentials: Array<{
        credentialSubject: CredentialSubject | CredentialSubject[];
        type?: string | string[];
        validFrom?: string;
        validUntil?: string;
        context?: string | string[];
        id?: string;
    }>): Promise<VerifiableCredential[]>;
}
//# sourceMappingURL=issuer.d.ts.map