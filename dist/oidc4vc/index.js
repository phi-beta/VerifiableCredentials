"use strict";
/**
 * OpenID Connect for Verifiable Credentials (OIDC4VC) Implementation
 * Supports credential issuance and presentation according to OIDC4VCI and OIDC4VP specifications
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OIDC4VCClient = exports.OIDC4VPServer = exports.OIDC4VCIServer = void 0;
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const body_parser_1 = __importDefault(require("body-parser"));
const axios_1 = __importDefault(require("axios"));
const uuid_1 = require("uuid");
const utils_1 = require("../utils");
/**
 * OIDC4VCI Server - Credential Issuance Server
 */
class OIDC4VCIServer {
    constructor(config) {
        this.preAuthorizedCodes = new Map();
        this.accessTokens = new Map();
        this.issuedCredentials = new Map();
        this.config = config;
        this.app = (0, express_1.default)();
        this.setupMiddleware();
        this.setupRoutes();
    }
    setupMiddleware() {
        this.app.use((0, cors_1.default)());
        this.app.use(body_parser_1.default.json());
        this.app.use(body_parser_1.default.urlencoded({ extended: true }));
    }
    setupRoutes() {
        // Well-known configuration endpoint
        this.app.get('/.well-known/openid_credential_issuer', this.getIssuerMetadata.bind(this));
        // OAuth 2.0 token endpoint
        this.app.post('/token', this.handleTokenRequest.bind(this));
        // Credential endpoint
        this.app.post('/credential', this.handleCredentialRequest.bind(this));
        // Credential offer endpoint (custom)
        this.app.post('/credential-offer', this.createCredentialOffer.bind(this));
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({ status: 'healthy', timestamp: (0, utils_1.getCurrentDateTime)() });
        });
    }
    async getIssuerMetadata(req, res) {
        try {
            const metadata = {
                credential_issuer: this.config.issuerUrl,
                authorization_server: this.config.issuerUrl,
                credential_endpoint: `${this.config.issuerUrl}/credential`,
                token_endpoint: `${this.config.issuerUrl}/token`,
                credentials_supported: this.config.supportedCredentialTypes.map(type => ({
                    format: 'ldp_vc',
                    id: type,
                    types: ['VerifiableCredential', type],
                    '@context': [
                        'https://www.w3.org/2018/credentials/v1',
                        'https://www.w3.org/2018/credentials/examples/v1'
                    ],
                    cryptographic_binding_methods_supported: ['did:key'],
                    credential_signing_alg_values_supported: ['Ed25519Signature2020'],
                    proof_types_supported: {
                        jwt: {
                            proof_signing_alg_values_supported: ['EdDSA']
                        }
                    }
                })),
                grant_types_supported: [
                    'authorization_code',
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code'
                ],
                response_types_supported: ['code'],
                scopes_supported: ['openid'],
                subject_types_supported: ['public'],
                id_token_signing_alg_values_supported: ['EdDSA'],
                request_object_signing_alg_values_supported: ['EdDSA'],
                token_endpoint_auth_methods_supported: ['client_secret_basic', 'none']
            };
            res.json(metadata);
        }
        catch (error) {
            console.error('Error getting issuer metadata:', error);
            res.status(500).json({ error: 'internal_server_error' });
        }
    }
    async handleTokenRequest(req, res) {
        try {
            const { grant_type, code, pre_authorized_code } = req.body;
            if (grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
                // Pre-authorized code flow
                const codeData = this.preAuthorizedCodes.get(pre_authorized_code);
                if (!codeData) {
                    return res.status(400).json({ error: 'invalid_grant' });
                }
                // Generate access token
                const accessToken = (0, uuid_1.v4)();
                const tokenData = {
                    credential_types: codeData.credential_types,
                    subject: codeData.subject,
                    expires_at: Date.now() + 3600000 // 1 hour
                };
                this.accessTokens.set(accessToken, tokenData);
                this.preAuthorizedCodes.delete(pre_authorized_code);
                return res.json({
                    access_token: accessToken,
                    token_type: 'Bearer',
                    expires_in: 3600,
                    c_nonce: (0, uuid_1.v4)(),
                    c_nonce_expires_in: 86400
                });
            }
            else {
                return res.status(400).json({ error: 'unsupported_grant_type' });
            }
        }
        catch (error) {
            console.error('Error handling token request:', error);
            return res.status(500).json({ error: 'internal_server_error' });
        }
    }
    async handleCredentialRequest(req, res) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'invalid_token' });
            }
            const accessToken = authHeader.substring(7);
            const tokenData = this.accessTokens.get(accessToken);
            if (!tokenData || tokenData.expires_at < Date.now()) {
                return res.status(401).json({ error: 'invalid_token' });
            }
            const credentialRequest = req.body;
            // Validate credential type
            if (!tokenData.credential_types.includes(credentialRequest.type)) {
                return res.status(400).json({ error: 'unsupported_credential_type' });
            }
            // Issue the credential
            const credential = await this.config.issuer.issueCredential({
                credentialSubject: tokenData.subject,
                type: ['VerifiableCredential', credentialRequest.type],
                validFrom: (0, utils_1.getCurrentDateTime)()
            });
            // Store for tracking
            this.issuedCredentials.set(credential.id, credential);
            const response = {
                credential,
                c_nonce: (0, uuid_1.v4)(),
                c_nonce_expires_in: 86400
            };
            return res.json(response);
        }
        catch (error) {
            console.error('Error handling credential request:', error);
            return res.status(500).json({ error: 'internal_server_error' });
        }
    }
    async createCredentialOffer(req, res) {
        try {
            const { credential_types, subject } = req.body;
            // Generate pre-authorized code
            const preAuthorizedCode = (0, uuid_1.v4)();
            const codeData = {
                credential_types,
                subject,
                created_at: Date.now()
            };
            this.preAuthorizedCodes.set(preAuthorizedCode, codeData);
            const credentialOffer = {
                credential_issuer: this.config.issuerUrl,
                credentials: credential_types,
                grants: {
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                        'pre-authorized_code': preAuthorizedCode,
                        user_pin_required: false
                    }
                }
            };
            res.json({
                credential_offer: credentialOffer,
                credential_offer_uri: `${this.config.issuerUrl}/credential-offer?id=${preAuthorizedCode}`
            });
        }
        catch (error) {
            console.error('Error creating credential offer:', error);
            res.status(500).json({ error: 'internal_server_error' });
        }
    }
    start() {
        return new Promise((resolve) => {
            this.app.listen(this.config.port, () => {
                console.log(`🔐 OIDC4VCI Server running on ${this.config.issuerUrl}`);
                resolve();
            });
        });
    }
    getIssuedCredentials() {
        return Array.from(this.issuedCredentials.values());
    }
}
exports.OIDC4VCIServer = OIDC4VCIServer;
/**
 * OIDC4VP Server - Credential Presentation Verifier
 */
class OIDC4VPServer {
    constructor(config) {
        this.authorizationRequests = new Map();
        this.verificationResults = new Map();
        this.config = config;
        this.app = (0, express_1.default)();
        this.setupMiddleware();
        this.setupRoutes();
    }
    setupMiddleware() {
        this.app.use((0, cors_1.default)());
        this.app.use(body_parser_1.default.json());
        this.app.use(body_parser_1.default.urlencoded({ extended: true }));
    }
    setupRoutes() {
        // Well-known configuration endpoint
        this.app.get('/.well-known/openid_credential_verifier', this.getVerifierMetadata.bind(this));
        // Authorization request endpoint
        this.app.post('/authorize', this.createAuthorizationRequest.bind(this));
        // Presentation submission endpoint
        this.app.post('/presentation', this.handlePresentationSubmission.bind(this));
        // Verification result endpoint
        this.app.get('/result/:state', this.getVerificationResult.bind(this));
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({ status: 'healthy', timestamp: (0, utils_1.getCurrentDateTime)() });
        });
    }
    async getVerifierMetadata(req, res) {
        try {
            const metadata = {
                issuer: this.config.verifierUrl,
                authorization_endpoint: `${this.config.verifierUrl}/authorize`,
                response_types_supported: ['vp_token'],
                response_modes_supported: ['direct_post'],
                scopes_supported: ['openid'],
                subject_types_supported: ['public'],
                vp_formats_supported: {
                    ldp_vp: {
                        proof_type: ['Ed25519Signature2020']
                    },
                    jwt_vp: {
                        alg: ['EdDSA']
                    }
                },
                request_object_signing_alg_values_supported: ['EdDSA'],
                presentation_definition_uri_supported: true
            };
            res.json(metadata);
        }
        catch (error) {
            console.error('Error getting verifier metadata:', error);
            res.status(500).json({ error: 'internal_server_error' });
        }
    }
    async createAuthorizationRequest(req, res) {
        try {
            const { credential_types, purpose } = req.body;
            const state = (0, uuid_1.v4)();
            const nonce = (0, uuid_1.v4)();
            const presentationRequest = {
                client_id: this.config.clientId,
                response_type: 'vp_token',
                scope: 'openid',
                state,
                nonce,
                response_mode: 'direct_post',
                response_uri: `${this.config.verifierUrl}/presentation`,
                presentation_definition: {
                    id: (0, uuid_1.v4)(),
                    input_descriptors: credential_types.map((type, index) => ({
                        id: `input_${index}`,
                        constraints: {
                            fields: [
                                {
                                    path: ['$.type'],
                                    filter: {
                                        type: 'array',
                                        contains: {
                                            const: type
                                        }
                                    }
                                }
                            ]
                        }
                    }))
                }
            };
            this.authorizationRequests.set(state, presentationRequest);
            res.json({
                authorization_request: presentationRequest,
                request_uri: `${this.config.verifierUrl}/authorize?state=${state}`
            });
        }
        catch (error) {
            console.error('Error creating authorization request:', error);
            res.status(500).json({ error: 'internal_server_error' });
        }
    }
    async handlePresentationSubmission(req, res) {
        try {
            const authResponse = req.body;
            const authRequest = this.authorizationRequests.get(authResponse.state);
            if (!authRequest) {
                return res.status(400).json({ error: 'invalid_state' });
            }
            // Parse and verify the presentation
            let presentation;
            try {
                // Assume vp_token is a JSON string of the presentation
                presentation = JSON.parse(authResponse.vp_token);
            }
            catch {
                return res.status(400).json({ error: 'invalid_vp_token' });
            }
            // Verify the presentation
            const verificationResult = await this.config.verifier.verifyPresentation(presentation, {
                challenge: authRequest.nonce,
                domain: this.config.verifierUrl
            });
            // Store verification result
            this.verificationResults.set(authResponse.state, verificationResult);
            // Clean up
            this.authorizationRequests.delete(authResponse.state);
            if (verificationResult.valid) {
                return res.json({
                    status: 'success',
                    redirect_uri: `${this.config.redirectUri}?state=${authResponse.state}&result=success`
                });
            }
            else {
                return res.status(400).json({
                    error: 'invalid_presentation',
                    error_description: verificationResult.errors.join(', ')
                });
            }
        }
        catch (error) {
            console.error('Error handling presentation submission:', error);
            return res.status(500).json({ error: 'internal_server_error' });
        }
    }
    async getVerificationResult(req, res) {
        try {
            const { state } = req.params;
            const result = this.verificationResults.get(state);
            if (!result) {
                return res.status(404).json({ error: 'result_not_found' });
            }
            return res.json(result);
        }
        catch (error) {
            console.error('Error getting verification result:', error);
            return res.status(500).json({ error: 'internal_server_error' });
        }
    }
    start() {
        return new Promise((resolve) => {
            this.app.listen(this.config.port, () => {
                console.log(`🔍 OIDC4VP Server running on ${this.config.verifierUrl}`);
                resolve();
            });
        });
    }
    getVerificationResults() {
        return this.verificationResults;
    }
}
exports.OIDC4VPServer = OIDC4VPServer;
/**
 * OIDC4VC Client - For interacting with OIDC4VCI and OIDC4VP servers
 */
class OIDC4VCClient {
    constructor(holder) {
        this.holder = holder;
    }
    /**
     * Accept a credential offer from an OIDC4VCI server
     */
    async acceptCredentialOffer(credentialOfferUri) {
        try {
            // Get the credential offer
            const offerResponse = await axios_1.default.get(credentialOfferUri);
            const credentialOffer = offerResponse.data;
            // Get issuer metadata
            const metadataResponse = await axios_1.default.get(`${credentialOffer.credential_issuer}/.well-known/openid_credential_issuer`);
            const issuerMetadata = metadataResponse.data;
            // Exchange pre-authorized code for access token
            const grant = credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
            if (!grant) {
                throw new Error('Only pre-authorized code flow is supported');
            }
            const tokenResponse = await axios_1.default.post(issuerMetadata.token_endpoint, {
                grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
                'pre-authorized_code': grant['pre-authorized_code']
            });
            const { access_token } = tokenResponse.data;
            // Request credential
            const credentialResponse = await axios_1.default.post(issuerMetadata.credential_endpoint, {
                type: credentialOffer.credentials[0],
                format: 'ldp_vc'
            }, {
                headers: {
                    Authorization: `Bearer ${access_token}`,
                    'Content-Type': 'application/json'
                }
            });
            const credential = credentialResponse.data.credential;
            // Store the credential
            this.holder.storeCredential(credential);
            return credential;
        }
        catch (error) {
            throw new Error(`Failed to accept credential offer: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    /**
     * Submit a presentation to an OIDC4VP verifier
     */
    async submitPresentation(authorizationRequestUri, credentialTypes) {
        try {
            // Get authorization request
            const authResponse = await axios_1.default.get(authorizationRequestUri);
            const authRequest = authResponse.data.authorization_request;
            // Find matching credentials
            const matchingCredentials = [];
            for (const type of credentialTypes) {
                const credentials = this.holder.getCredentialsByType(type);
                if (credentials.length > 0) {
                    matchingCredentials.push(credentials[0]); // Take the first matching credential
                }
            }
            if (matchingCredentials.length === 0) {
                throw new Error('No matching credentials found');
            }
            // Create presentation
            const presentation = await this.holder.createPresentation({
                verifiableCredential: matchingCredentials,
                type: ['VerifiablePresentation'],
                challenge: authRequest.nonce,
                domain: authRequest.response_uri
            });
            // Submit presentation
            const submissionResponse = await axios_1.default.post(authRequest.response_uri, {
                vp_token: JSON.stringify(presentation),
                presentation_submission: {
                    id: (0, uuid_1.v4)(),
                    definition_id: authRequest.presentation_definition.id,
                    descriptor_map: matchingCredentials.map((_, index) => ({
                        id: authRequest.presentation_definition.input_descriptors[index].id,
                        format: 'ldp_vp',
                        path: `$.verifiableCredential[${index}]`
                    }))
                },
                state: authRequest.state
            });
            return submissionResponse.data.redirect_uri || 'Presentation submitted successfully';
        }
        catch (error) {
            throw new Error(`Failed to submit presentation: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}
exports.OIDC4VCClient = OIDC4VCClient;
exports.default = {
    OIDC4VCIServer,
    OIDC4VPServer,
    OIDC4VCClient
};
//# sourceMappingURL=index.js.map