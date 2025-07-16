/**
 * Issuer implementation for W3C Verifiable Credentials
 * Handles credential issuance and signing
 */

import { v4 as uuidv4 } from 'uuid';
import { VerifiableCredential, Issuer as IssuerType, CredentialSubject, Proof } from '../types';
import { W3C_VC_CONTEXT_V2 } from '../context';
import { SecurityManager } from '../security';

export interface IssuerOptions {
  id: string;
  name?: string;
  description?: string;
  url?: string;
  image?: string;
  keyPair?: any; // Will be properly typed when we implement cryptographic keys
}

export class Issuer {
  private issuerInfo: IssuerType;
  private securityManager: SecurityManager;

  constructor(options: IssuerOptions) {
    this.issuerInfo = {
      id: options.id,
      name: options.name,
      description: options.description,
      url: options.url,
      image: options.image
    };
    
    this.securityManager = new SecurityManager();
  }

  /**
   * Issue a new verifiable credential
   */
  async issueCredential(options: {
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
  }): Promise<VerifiableCredential> {
    const now = new Date().toISOString();
    const credentialId = options.id || `urn:uuid:${uuidv4()}`;
    
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
    const typeArray: string[] = ['VerifiableCredential'];
    if (options.type) {
      if (Array.isArray(options.type)) {
        typeArray.push(...options.type);
      } else {
        typeArray.push(options.type);
      }
    }

    // Create the unsigned credential
    const credential: VerifiableCredential = {
      '@context': contextArray,
      id: credentialId,
      type: typeArray,
      issuer: this.issuerInfo,
      validFrom: options.validFrom || now,
      credentialSubject: options.credentialSubject
    };

    // Add optional fields
    if (options.validUntil) {
      credential.validUntil = options.validUntil;
    }
    if (options.credentialStatus) {
      credential.credentialStatus = options.credentialStatus;
    }
    if (options.credentialSchema) {
      credential.credentialSchema = options.credentialSchema;
    }
    if (options.evidence) {
      credential.evidence = options.evidence;
    }
    if (options.refreshService) {
      credential.refreshService = options.refreshService;
    }
    if (options.termsOfUse) {
      credential.termsOfUse = options.termsOfUse;
    }

    // Sign the credential
    const signedCredential = await this.signCredential(credential);
    
    return signedCredential;
  }

  /**
   * Sign a credential with the issuer's private key
   */
  private async signCredential(credential: VerifiableCredential): Promise<VerifiableCredential> {
    try {
      // For now, create a simple proof structure
      // In a real implementation, this would use proper cryptographic signing
      const proof: Proof = {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: `${this.issuerInfo.id}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: await this.securityManager.sign(credential, 'placeholder-key')
      };

      return {
        ...credential,
        proof
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to sign credential: ${errorMessage}`);
    }
  }

  /**
   * Revoke a credential (update its status)
   */
  async revokeCredential(credentialId: string, reason?: string): Promise<void> {
    // Implementation would update the credential status
    // This is a placeholder for the revocation logic
    console.log(`Revoking credential ${credentialId}${reason ? ` with reason: ${reason}` : ''}`);
    
    // In a real implementation, this would:
    // 1. Update the credential status list
    // 2. Publish the updated status
    // 3. Optionally notify holders
  }

  /**
   * Get issuer information
   */
  getIssuerInfo(): IssuerType {
    return { ...this.issuerInfo };
  }

  /**
   * Update issuer information
   */
  updateIssuerInfo(updates: Partial<IssuerOptions>): void {
    this.issuerInfo = {
      ...this.issuerInfo,
      ...updates
    };
  }

  /**
   * Batch issue multiple credentials
   */
  async batchIssueCredentials(credentials: Array<{
    credentialSubject: CredentialSubject | CredentialSubject[];
    type?: string | string[];
    validFrom?: string;
    validUntil?: string;
    context?: string | string[];
    id?: string;
  }>): Promise<VerifiableCredential[]> {
    const issuedCredentials: VerifiableCredential[] = [];
    
    for (const credentialOptions of credentials) {
      try {
        const credential = await this.issueCredential(credentialOptions);
        issuedCredentials.push(credential);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to issue credential in batch: ${errorMessage}`);
      }
    }
    
    return issuedCredentials;
  }
}
