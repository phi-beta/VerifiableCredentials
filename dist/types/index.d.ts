/**
 * Core types and interfaces for W3C Verifiable Credentials Data Model v2.0
 * Based on: https://www.w3.org/TR/vc-data-model/
 */
export type URI = string;
export type DateTime = string;
export type ID = string;
export interface VerifiableCredential {
    '@context': string | string[];
    id?: ID;
    type: string | string[];
    issuer: URI | Issuer;
    validFrom?: DateTime;
    validUntil?: DateTime;
    credentialSubject: CredentialSubject | CredentialSubject[];
    proof?: Proof | Proof[];
    credentialStatus?: CredentialStatus;
    credentialSchema?: CredentialSchema;
    refreshService?: RefreshService;
    termsOfUse?: TermsOfUse[];
    evidence?: Evidence[];
}
export interface VerifiablePresentation {
    '@context': string | string[];
    id?: ID;
    type: string | string[];
    verifiableCredential?: VerifiableCredential[];
    holder?: URI;
    proof?: Proof | Proof[];
    termsOfUse?: TermsOfUse[];
}
export interface Issuer {
    id: URI;
    name?: string;
    description?: string;
    url?: URI;
    image?: URI;
    [key: string]: any;
}
export interface CredentialSubject {
    id?: URI;
    [key: string]: any;
}
export interface Proof {
    type: string;
    created?: DateTime;
    verificationMethod?: URI;
    proofPurpose?: string;
    challenge?: string;
    domain?: string;
    proofValue?: string;
    jws?: string;
    [key: string]: any;
}
export interface CredentialStatus {
    id: URI;
    type: string;
    statusPurpose?: string;
    statusListIndex?: string;
    statusListCredential?: URI;
    [key: string]: any;
}
export interface CredentialSchema {
    id: URI;
    type: string;
    [key: string]: any;
}
export interface RefreshService {
    id: URI;
    type: string;
    [key: string]: any;
}
export interface TermsOfUse {
    type: string;
    id?: URI;
    profile?: URI;
    prohibition?: Prohibition[];
    [key: string]: any;
}
export interface Prohibition {
    assigner?: URI;
    assignee?: URI;
    target?: URI;
    action?: string[];
    [key: string]: any;
}
export interface Evidence {
    id?: URI;
    type: string[];
    [key: string]: any;
}
export interface ValidationResult {
    valid: boolean;
    errors: string[];
    warnings?: string[];
}
//# sourceMappingURL=index.d.ts.map