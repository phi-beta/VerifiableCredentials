/**
 * Holder implementation for W3C Verifiable Credentials
 * Handles credential storage, presentation creation, and selective disclosure
 */

import { v4 as uuidv4 } from 'uuid';
import { VerifiableCredential, VerifiablePresentation, Proof } from '../types';
import { W3C_VC_CONTEXT_V2 } from '../context';
import { SecurityManager } from '../security';

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

export class Holder {
  private holderId: string;
  private name?: string;
  private credentials: Map<string, VerifiableCredential> = new Map();
  private securityManager: SecurityManager;

  constructor(options: HolderOptions) {
    this.holderId = options.id;
    this.name = options.name;
    this.securityManager = new SecurityManager();
  }

  /**
   * Store a verifiable credential
   */
  storeCredential(credential: VerifiableCredential): void {
    if (!credential.id) {
      throw new Error('Credential must have an ID to be stored');
    }
    
    this.credentials.set(credential.id, credential);
  }

  /**
   * Retrieve a stored credential by ID
   */
  getCredential(credentialId: string): VerifiableCredential | undefined {
    return this.credentials.get(credentialId);
  }

  /**
   * List all stored credentials
   */
  listCredentials(): VerifiableCredential[] {
    return Array.from(this.credentials.values());
  }

  /**
   * Remove a credential from storage
   */
  removeCredential(credentialId: string): boolean {
    return this.credentials.delete(credentialId);
  }

  /**
   * Create a verifiable presentation
   */
  async createPresentation(options: PresentationOptions): Promise<VerifiablePresentation> {
    const now = new Date().toISOString();
    const presentationId = options.id || `urn:uuid:${uuidv4()}`;
    
    // Build the context array
    const contextArray: string[] = [W3C_VC_CONTEXT_V2];
    if (options.context) {
      if (Array.isArray(options.context)) {
        contextArray.push(...options.context);
      } else {
        contextArray.push(options.context);
      }
    }

    // Build the type array
    const typeArray: string[] = ['VerifiablePresentation'];
    if (options.type) {
      if (Array.isArray(options.type)) {
        typeArray.push(...options.type);
      } else {
        typeArray.push(options.type);
      }
    }

    // Create the unsigned presentation
    const presentation: VerifiablePresentation = {
      '@context': contextArray,
      id: presentationId,
      type: typeArray,
      holder: options.holder || this.holderId
    };

    // Add verifiable credentials if provided
    if (options.verifiableCredential && options.verifiableCredential.length > 0) {
      presentation.verifiableCredential = options.verifiableCredential;
    }

    // Add optional fields
    if (options.termsOfUse) {
      presentation.termsOfUse = options.termsOfUse;
    }

    // Sign the presentation
    const signedPresentation = await this.signPresentation(presentation, {
      challenge: options.challenge,
      domain: options.domain
    });
    
    return signedPresentation;
  }

  /**
   * Sign a presentation with the holder's private key
   */
  private async signPresentation(
    presentation: VerifiablePresentation,
    options: { challenge?: string; domain?: string }
  ): Promise<VerifiablePresentation> {
    try {
      const proof: Proof = {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: `${this.holderId}#key-1`,
        proofPurpose: 'authentication'
      };

      // Add challenge and domain if provided
      if (options.challenge) {
        proof.challenge = options.challenge;
      }
      if (options.domain) {
        proof.domain = options.domain;
      }

      // Sign the presentation
      proof.proofValue = await this.securityManager.sign(presentation, 'placeholder-key');

      return {
        ...presentation,
        proof
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to sign presentation: ${errorMessage}`);
    }
  }

  /**
   * Create a presentation from specific credentials
   */
  async createPresentationFromCredentials(
    credentialIds: string[],
    options: Omit<PresentationOptions, 'verifiableCredential'> = {}
  ): Promise<VerifiablePresentation> {
    const selectedCredentials: VerifiableCredential[] = [];
    
    for (const credentialId of credentialIds) {
      const credential = this.getCredential(credentialId);
      if (!credential) {
        throw new Error(`Credential with ID ${credentialId} not found`);
      }
      selectedCredentials.push(credential);
    }

    return this.createPresentation({
      ...options,
      verifiableCredential: selectedCredentials
    });
  }

  /**
   * Filter credentials by type
   */
  getCredentialsByType(type: string): VerifiableCredential[] {
    return this.listCredentials().filter(credential => {
      const types = Array.isArray(credential.type) ? credential.type : [credential.type];
      return types.includes(type);
    });
  }

  /**
   * Filter credentials by issuer
   */
  getCredentialsByIssuer(issuerUri: string): VerifiableCredential[] {
    return this.listCredentials().filter(credential => {
      const issuer = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
      return issuer === issuerUri;
    });
  }

  /**
   * Check if a credential is expired
   */
  isCredentialExpired(credential: VerifiableCredential): boolean {
    if (!credential.validUntil) {
      return false; // No expiration date means it doesn't expire
    }
    
    const now = new Date();
    const expiration = new Date(credential.validUntil);
    return now > expiration;
  }

  /**
   * Get valid (non-expired) credentials
   */
  getValidCredentials(): VerifiableCredential[] {
    return this.listCredentials().filter(credential => !this.isCredentialExpired(credential));
  }

  /**
   * Get expired credentials
   */
  getExpiredCredentials(): VerifiableCredential[] {
    return this.listCredentials().filter(credential => this.isCredentialExpired(credential));
  }

  /**
   * Get holder information
   */
  getHolderInfo(): { id: string; name?: string } {
    return {
      id: this.holderId,
      name: this.name
    };
  }

  /**
   * Update holder information
   */
  updateHolderInfo(updates: { name?: string }): void {
    if (updates.name !== undefined) {
      this.name = updates.name;
    }
  }

  /**
   * Export credentials as JSON
   */
  exportCredentials(): string {
    const credentials = this.listCredentials();
    return JSON.stringify(credentials, null, 2);
  }

  /**
   * Import credentials from JSON
   */
  importCredentials(credentialsJson: string): void {
    try {
      const credentials = JSON.parse(credentialsJson);
      if (!Array.isArray(credentials)) {
        throw new Error('Invalid credentials format');
      }
      
      for (const credential of credentials) {
        if (credential.id) {
          this.storeCredential(credential);
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to import credentials: ${errorMessage}`);
    }
  }
}
