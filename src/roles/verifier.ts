/**
 * Verifier implementation for W3C Verifiable Credentials
 * Handles credential and presentation verification
 */

import { VerifiableCredential, VerifiablePresentation, ValidationResult, Proof } from '../types';
import { ContextManager } from '../context';
import { SecurityManager } from '../security';

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

export class Verifier {
  private verifierId: string;
  private name?: string;
  private trustedIssuers: Set<string>;
  private requiredProofPurposes: Set<string>;
  private contextManager: ContextManager;
  private securityManager: SecurityManager;

  constructor(options: VerifierOptions) {
    this.verifierId = options.id;
    this.name = options.name;
    this.trustedIssuers = new Set(options.trustedIssuers || []);
    this.requiredProofPurposes = new Set(options.requiredProofPurposes || ['assertionMethod']);
    this.contextManager = new ContextManager();
    this.securityManager = new SecurityManager();
  }

  /**
   * Verify a verifiable credential
   */
  async verifyCredential(
    credential: VerifiableCredential,
    options: VerificationOptions = {}
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Basic structure validation
      const structureResult = await this.validateCredentialStructure(credential);
      if (!structureResult.valid) {
        errors.push(...structureResult.errors);
        warnings.push(...(structureResult.warnings || []));
      }

      // Context validation
      const contextResult = await this.contextManager.validateContext(credential);
      if (!contextResult.valid) {
        errors.push(...contextResult.errors);
        warnings.push(...(contextResult.warnings || []));
      }

      // Issuer validation
      const issuerResult = this.validateIssuer(credential, options.trustedIssuers);
      if (!issuerResult.valid) {
        errors.push(...issuerResult.errors);
        warnings.push(...(issuerResult.warnings || []));
      }

      // Expiration validation
      if (options.checkExpiration !== false) {
        const expirationResult = this.validateExpiration(credential);
        if (!expirationResult.valid) {
          errors.push(...expirationResult.errors);
          warnings.push(...(expirationResult.warnings || []));
        }
      }

      // Proof validation
      if (credential.proof) {
        const proofResult = await this.validateProof(credential, credential.proof);
        if (!proofResult.valid) {
          errors.push(...proofResult.errors);
          warnings.push(...(proofResult.warnings || []));
        }
      } else {
        warnings.push('No proof found in credential');
      }

      // Revocation status check
      if (options.checkRevocation && credential.credentialStatus) {
        const revocationResult = await this.checkRevocationStatus(credential);
        if (!revocationResult.valid) {
          errors.push(...revocationResult.errors);
          warnings.push(...(revocationResult.warnings || []));
        }
      }

      return { valid: errors.length === 0, errors, warnings };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Credential verification failed: ${errorMessage}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Verify a verifiable presentation
   */
  async verifyPresentation(
    presentation: VerifiablePresentation,
    options: VerificationOptions = {}
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Basic structure validation
      const structureResult = await this.validatePresentationStructure(presentation);
      if (!structureResult.valid) {
        errors.push(...structureResult.errors);
        warnings.push(...(structureResult.warnings || []));
      }

      // Context validation
      const contextResult = await this.contextManager.validateContext(presentation);
      if (!contextResult.valid) {
        errors.push(...contextResult.errors);
        warnings.push(...(contextResult.warnings || []));
      }

      // Presentation proof validation
      if (presentation.proof) {
        const proofResult = await this.validatePresentationProof(presentation, options);
        if (!proofResult.valid) {
          errors.push(...proofResult.errors);
          warnings.push(...(proofResult.warnings || []));
        }
      } else {
        warnings.push('No proof found in presentation');
      }

      // Verify each credential in the presentation
      if (presentation.verifiableCredential) {
        for (let i = 0; i < presentation.verifiableCredential.length; i++) {
          const credential = presentation.verifiableCredential[i];
          const credentialResult = await this.verifyCredential(credential, options);
          
          if (!credentialResult.valid) {
            errors.push(...credentialResult.errors.map(err => `Credential ${i}: ${err}`));
          }
          if (credentialResult.warnings) {
            warnings.push(...credentialResult.warnings.map(warn => `Credential ${i}: ${warn}`));
          }
        }
      }

      return { valid: errors.length === 0, errors, warnings };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Presentation verification failed: ${errorMessage}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Validate credential structure
   */
  private async validateCredentialStructure(credential: VerifiableCredential): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check required fields
    if (!credential['@context']) {
      errors.push('Missing @context field');
    }
    if (!credential.type) {
      errors.push('Missing type field');
    }
    if (!credential.issuer) {
      errors.push('Missing issuer field');
    }
    if (!credential.credentialSubject) {
      errors.push('Missing credentialSubject field');
    }

    // Check type includes VerifiableCredential
    const types = Array.isArray(credential.type) ? credential.type : [credential.type];
    if (!types.includes('VerifiableCredential')) {
      errors.push('Type must include VerifiableCredential');
    }

    // Validate dates
    if (credential.validFrom) {
      try {
        new Date(credential.validFrom);
      } catch {
        errors.push('Invalid validFrom date format');
      }
    }
    if (credential.validUntil) {
      try {
        new Date(credential.validUntil);
      } catch {
        errors.push('Invalid validUntil date format');
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate presentation structure
   */
  private async validatePresentationStructure(presentation: VerifiablePresentation): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check required fields
    if (!presentation['@context']) {
      errors.push('Missing @context field');
    }
    if (!presentation.type) {
      errors.push('Missing type field');
    }

    // Check type includes VerifiablePresentation
    const types = Array.isArray(presentation.type) ? presentation.type : [presentation.type];
    if (!types.includes('VerifiablePresentation')) {
      errors.push('Type must include VerifiablePresentation');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate issuer
   */
  private validateIssuer(credential: VerifiableCredential, trustedIssuers?: string[]): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    const issuerUri = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
    
    // Check if issuer is in trusted list
    const trustedList = trustedIssuers || Array.from(this.trustedIssuers);
    if (trustedList.length > 0 && !trustedList.includes(issuerUri)) {
      errors.push(`Issuer ${issuerUri} is not in trusted issuers list`);
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate expiration
   */
  private validateExpiration(credential: VerifiableCredential): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const now = new Date();

    // Check validFrom
    if (credential.validFrom) {
      const validFrom = new Date(credential.validFrom);
      if (now < validFrom) {
        errors.push('Credential is not yet valid');
      }
    }

    // Check validUntil
    if (credential.validUntil) {
      const validUntil = new Date(credential.validUntil);
      if (now > validUntil) {
        errors.push('Credential has expired');
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate proof
   */
  private async validateProof(credential: VerifiableCredential, proof: Proof | Proof[]): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    const proofs = Array.isArray(proof) ? proof : [proof];

    for (const singleProof of proofs) {
      // For now, perform basic validation
      // In a real implementation, this would verify the actual cryptographic proof
      if (!singleProof.type) {
        errors.push('Proof missing type');
      }
      if (!singleProof.verificationMethod) {
        errors.push('Proof missing verificationMethod');
      }
      if (!singleProof.proofPurpose) {
        errors.push('Proof missing proofPurpose');
      }
      if (!singleProof.proofValue && !singleProof.jws) {
        errors.push('Proof missing proofValue or jws');
      }

      // Check proof purpose
      if (singleProof.proofPurpose && !this.requiredProofPurposes.has(singleProof.proofPurpose)) {
        warnings.push(`Proof purpose ${singleProof.proofPurpose} is not in required purposes`);
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate presentation proof
   */
  private async validatePresentationProof(
    presentation: VerifiablePresentation,
    options: VerificationOptions
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!presentation.proof) {
      return { valid: true, errors, warnings };
    }

    const proofs = Array.isArray(presentation.proof) ? presentation.proof : [presentation.proof];

    for (const proof of proofs) {
      // Check challenge if required
      if (options.challenge && proof.challenge !== options.challenge) {
        errors.push('Proof challenge does not match required challenge');
      }

      // Check domain if required
      if (options.domain && proof.domain !== options.domain) {
        errors.push('Proof domain does not match required domain');
      }

      // Basic proof validation (for presentations, we validate the proof structure)
      if (!proof.type) {
        errors.push('Proof missing type');
      }
      if (!proof.verificationMethod) {
        errors.push('Proof missing verificationMethod');
      }
      if (!proof.proofPurpose) {
        errors.push('Proof missing proofPurpose');
      }
      if (!proof.proofValue && !proof.jws) {
        errors.push('Proof missing proofValue or jws');
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Check revocation status
   */
  private async checkRevocationStatus(credential: VerifiableCredential): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Placeholder for revocation checking
    // In a real implementation, this would check the credential status
    if (credential.credentialStatus) {
      // For now, assume credentials are not revoked
      warnings.push('Revocation checking not fully implemented');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Add trusted issuer
   */
  addTrustedIssuer(issuerUri: string): void {
    this.trustedIssuers.add(issuerUri);
  }

  /**
   * Remove trusted issuer
   */
  removeTrustedIssuer(issuerUri: string): void {
    this.trustedIssuers.delete(issuerUri);
  }

  /**
   * Get trusted issuers
   */
  getTrustedIssuers(): string[] {
    return Array.from(this.trustedIssuers);
  }

  /**
   * Get verifier information
   */
  getVerifierInfo(): { id: string; name?: string } {
    return {
      id: this.verifierId,
      name: this.name
    };
  }
}
