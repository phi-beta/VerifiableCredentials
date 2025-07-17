/**
 * OpenID Connect for Verifiable Credentials (OIDC4VC) Implementation
 * Supports credential issuance and presentation according to OIDC4VCI and OIDC4VP specifications
 */

import express, { Request, Response, Application } from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { VerifiableCredential, VerifiablePresentation, ValidationResult } from '../types';
import { Issuer } from '../roles/issuer';
import { Holder } from '../roles/holder';
import { Verifier } from '../roles/verifier';
import { generateURI, getCurrentDateTime } from '../utils';

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
export class OIDC4VCIServer {
  private app: Application;
  private config: OIDC4VCIConfig;
  private preAuthorizedCodes: Map<string, any> = new Map();
  private accessTokens: Map<string, any> = new Map();
  private issuedCredentials: Map<string, VerifiableCredential> = new Map();

  constructor(config: OIDC4VCIConfig) {
    this.config = config;
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(cors());
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.urlencoded({ extended: true }));
  }

  private setupRoutes(): void {
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
      res.json({ status: 'healthy', timestamp: getCurrentDateTime() });
    });
  }

  private async getIssuerMetadata(req: Request, res: Response): Promise<void> {
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
    } catch (error) {
      console.error('Error getting issuer metadata:', error);
      res.status(500).json({ error: 'internal_server_error' });
    }
  }

  private async handleTokenRequest(req: Request, res: Response): Promise<Response | void> {
    try {
      const { grant_type, code, pre_authorized_code } = req.body;

      if (grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
        // Pre-authorized code flow
        const codeData = this.preAuthorizedCodes.get(pre_authorized_code);
        if (!codeData) {
          return res.status(400).json({ error: 'invalid_grant' });
        }

        // Generate access token
        const accessToken = uuidv4();
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
          c_nonce: uuidv4(),
          c_nonce_expires_in: 86400
        });
      } else {
        return res.status(400).json({ error: 'unsupported_grant_type' });
      }
    } catch (error) {
      console.error('Error handling token request:', error);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }

  private async handleCredentialRequest(req: Request, res: Response): Promise<Response | void> {
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

      const credentialRequest: CredentialRequest = req.body;
      
      // Validate credential type
      if (!tokenData.credential_types.includes(credentialRequest.type)) {
        return res.status(400).json({ error: 'unsupported_credential_type' });
      }

      // Issue the credential
      const credential = await this.config.issuer.issueCredential({
        credentialSubject: tokenData.subject,
        type: ['VerifiableCredential', credentialRequest.type],
        validFrom: getCurrentDateTime()
      });

      // Store for tracking
      this.issuedCredentials.set(credential.id!, credential);

      const response: CredentialResponse = {
        credential,
        c_nonce: uuidv4(),
        c_nonce_expires_in: 86400
      };

      return res.json(response);
    } catch (error) {
      console.error('Error handling credential request:', error);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }

  private async createCredentialOffer(req: Request, res: Response): Promise<void> {
    try {
      const { credential_types, subject } = req.body;

      // Generate pre-authorized code
      const preAuthorizedCode = uuidv4();
      const codeData = {
        credential_types,
        subject,
        created_at: Date.now()
      };

      this.preAuthorizedCodes.set(preAuthorizedCode, codeData);

      const credentialOffer: CredentialOffer = {
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
    } catch (error) {
      console.error('Error creating credential offer:', error);
      res.status(500).json({ error: 'internal_server_error' });
    }
  }

  public start(): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(this.config.port, () => {
        console.log(`🔐 OIDC4VCI Server running on ${this.config.issuerUrl}`);
        resolve();
      });
    });
  }

  public getIssuedCredentials(): VerifiableCredential[] {
    return Array.from(this.issuedCredentials.values());
  }
}

/**
 * OIDC4VP Server - Credential Presentation Verifier
 */
export class OIDC4VPServer {
  private app: Application;
  private config: OIDC4VPConfig;
  private authorizationRequests: Map<string, PresentationRequest> = new Map();
  private verificationResults: Map<string, ValidationResult> = new Map();

  constructor(config: OIDC4VPConfig) {
    this.config = config;
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(cors());
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.urlencoded({ extended: true }));
  }

  private setupRoutes(): void {
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
      res.json({ status: 'healthy', timestamp: getCurrentDateTime() });
    });
  }

  private async getVerifierMetadata(req: Request, res: Response): Promise<void> {
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
    } catch (error) {
      console.error('Error getting verifier metadata:', error);
      res.status(500).json({ error: 'internal_server_error' });
    }
  }

  private async createAuthorizationRequest(req: Request, res: Response): Promise<void> {
    try {
      const { credential_types, purpose } = req.body;
      
      const state = uuidv4();
      const nonce = uuidv4();

      const presentationRequest: PresentationRequest = {
        client_id: this.config.clientId,
        response_type: 'vp_token',
        scope: 'openid',
        state,
        nonce,
        response_mode: 'direct_post',
        response_uri: `${this.config.verifierUrl}/presentation`,
        presentation_definition: {
          id: uuidv4(),
          input_descriptors: credential_types.map((type: string, index: number) => ({
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
    } catch (error) {
      console.error('Error creating authorization request:', error);
      res.status(500).json({ error: 'internal_server_error' });
    }
  }

  private async handlePresentationSubmission(req: Request, res: Response): Promise<Response | void> {
    try {
      const authResponse: AuthorizationResponse = req.body;
      
      const authRequest = this.authorizationRequests.get(authResponse.state);
      if (!authRequest) {
        return res.status(400).json({ error: 'invalid_state' });
      }

      // Parse and verify the presentation
      let presentation: VerifiablePresentation;
      try {
        // Assume vp_token is a JSON string of the presentation
        presentation = JSON.parse(authResponse.vp_token);
      } catch {
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
      } else {
        return res.status(400).json({ 
          error: 'invalid_presentation',
          error_description: verificationResult.errors.join(', ')
        });
      }
    } catch (error) {
      console.error('Error handling presentation submission:', error);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }

  private async getVerificationResult(req: Request, res: Response): Promise<Response | void> {
    try {
      const { state } = req.params;
      const result = this.verificationResults.get(state);
      
      if (!result) {
        return res.status(404).json({ error: 'result_not_found' });
      }

      return res.json(result);
    } catch (error) {
      console.error('Error getting verification result:', error);
      return res.status(500).json({ error: 'internal_server_error' });
    }
  }

  public start(): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(this.config.port, () => {
        console.log(`🔍 OIDC4VP Server running on ${this.config.verifierUrl}`);
        resolve();
      });
    });
  }

  public getVerificationResults(): Map<string, ValidationResult> {
    return this.verificationResults;
  }
}

/**
 * OIDC4VC Client - For interacting with OIDC4VCI and OIDC4VP servers
 */
export class OIDC4VCClient {
  private holder: Holder;

  constructor(holder: Holder) {
    this.holder = holder;
  }

  /**
   * Accept a credential offer from an OIDC4VCI server
   */
  async acceptCredentialOffer(credentialOfferUri: string): Promise<VerifiableCredential> {
    try {
      // Get the credential offer
      const offerResponse = await axios.get(credentialOfferUri);
      const credentialOffer: CredentialOffer = offerResponse.data;

      // Get issuer metadata
      const metadataResponse = await axios.get(
        `${credentialOffer.credential_issuer}/.well-known/openid_credential_issuer`
      );
      const issuerMetadata = metadataResponse.data;

      // Exchange pre-authorized code for access token
      const grant = credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
      if (!grant) {
        throw new Error('Only pre-authorized code flow is supported');
      }

      const tokenResponse = await axios.post(issuerMetadata.token_endpoint, {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': grant['pre-authorized_code']
      });

      const { access_token } = tokenResponse.data;

      // Request credential
      const credentialResponse = await axios.post(
        issuerMetadata.credential_endpoint,
        {
          type: credentialOffer.credentials[0],
          format: 'ldp_vc'
        },
        {
          headers: {
            Authorization: `Bearer ${access_token}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const credential: VerifiableCredential = credentialResponse.data.credential;
      
      // Store the credential
      this.holder.storeCredential(credential);
      
      return credential;
    } catch (error) {
      throw new Error(`Failed to accept credential offer: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Submit a presentation to an OIDC4VP verifier
   */
  async submitPresentation(
    authorizationRequestUri: string,
    credentialTypes: string[]
  ): Promise<string> {
    try {
      // Get authorization request
      const authResponse = await axios.get(authorizationRequestUri);
      const authRequest: PresentationRequest = authResponse.data.authorization_request;

      // Find matching credentials
      const matchingCredentials: VerifiableCredential[] = [];
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
      const submissionResponse = await axios.post(authRequest.response_uri, {
        vp_token: JSON.stringify(presentation),
        presentation_submission: {
          id: uuidv4(),
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
    } catch (error) {
      throw new Error(`Failed to submit presentation: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export default {
  OIDC4VCIServer,
  OIDC4VPServer,
  OIDC4VCClient
};
