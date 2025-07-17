/**
 * OpenID Connect for Verifiable Credentials (OIDC4VC) Implementation
 * Supports credential issuance and presentation according to OIDC4VCI and OIDC4VP specifications
 */
import { VerifiableCredential, ValidationResult } from '../types';
import { Issuer } from '../roles/issuer';
import { Holder } from '../roles/holder';
import { Verifier } from '../roles/verifier';
export interface OIDC4VCIConfig {
    issuerUrl: string;
    port: number;
    supportedCredentialTypes: string[];
    issuer: Issuer;
    clientSecret?: string;
    tokenEndpoint?: string;
    credentialEndpoint?: string;
}
export interface OIDC4VPConfig {
    verifierUrl: string;
    port: number;
    verifier: Verifier;
    clientId: string;
    redirectUri: string;
}
export interface CredentialOffer {
    credential_issuer: string;
    credentials: string[];
    grants: {
        authorization_code?: {
            issuer_state?: string;
        };
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: {
            'pre-authorized_code': string;
            user_pin_required?: boolean;
        };
    };
}
export interface CredentialRequest {
    type: string;
    format: 'ldp_vc' | 'jwt_vc_json';
    proof?: {
        proof_type: 'jwt';
        jwt: string;
    };
}
export interface CredentialResponse {
    credential?: VerifiableCredential;
    acceptance_token?: string;
    c_nonce?: string;
    c_nonce_expires_in?: number;
}
export interface PresentationRequest {
    client_id: string;
    response_type: string;
    scope: string;
    state: string;
    nonce: string;
    response_mode: string;
    response_uri: string;
    presentation_definition: {
        id: string;
        input_descriptors: Array<{
            id: string;
            constraints: {
                fields: Array<{
                    path: string[];
                    filter?: any;
                }>;
            };
        }>;
    };
}
export interface AuthorizationResponse {
    vp_token: string;
    presentation_submission: {
        id: string;
        definition_id: string;
        descriptor_map: Array<{
            id: string;
            format: string;
            path: string;
        }>;
    };
    state: string;
}
/**
 * OIDC4VCI Server - Credential Issuance Server
 */
export declare class OIDC4VCIServer {
    private app;
    private config;
    private preAuthorizedCodes;
    private accessTokens;
    private issuedCredentials;
    constructor(config: OIDC4VCIConfig);
    private setupMiddleware;
    private setupRoutes;
    private getIssuerMetadata;
    private handleTokenRequest;
    private handleCredentialRequest;
    private createCredentialOffer;
    start(): Promise<void>;
    getIssuedCredentials(): VerifiableCredential[];
}
/**
 * OIDC4VP Server - Credential Presentation Verifier
 */
export declare class OIDC4VPServer {
    private app;
    private config;
    private authorizationRequests;
    private verificationResults;
    constructor(config: OIDC4VPConfig);
    private setupMiddleware;
    private setupRoutes;
    private getVerifierMetadata;
    private createAuthorizationRequest;
    private handlePresentationSubmission;
    private getVerificationResult;
    start(): Promise<void>;
    getVerificationResults(): Map<string, ValidationResult>;
}
/**
 * OIDC4VC Client - For interacting with OIDC4VCI and OIDC4VP servers
 */
export declare class OIDC4VCClient {
    private holder;
    constructor(holder: Holder);
    /**
     * Accept a credential offer from an OIDC4VCI server
     */
    acceptCredentialOffer(credentialOfferUri: string): Promise<VerifiableCredential>;
    /**
     * Submit a presentation to an OIDC4VP verifier
     */
    submitPresentation(authorizationRequestUri: string, credentialTypes: string[]): Promise<string>;
}
declare const _default: {
    OIDC4VCIServer: typeof OIDC4VCIServer;
    OIDC4VPServer: typeof OIDC4VPServer;
    OIDC4VCClient: typeof OIDC4VCClient;
};
export default _default;
//# sourceMappingURL=index.d.ts.map