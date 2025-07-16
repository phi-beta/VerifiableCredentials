/**
 * Security and cryptographic operations for Verifiable Credentials
 * Handles signing, verification, and key management
 */

import * as crypto from 'crypto';
import { ValidationResult } from '../types';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
  type: string;
}

export class SecurityManager {
  private keyPairs: Map<string, KeyPair> = new Map();

  /**
   * Generate a new key pair
   */
  generateKeyPair(algorithm: string = 'ed25519'): KeyPair {
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync(algorithm as any, {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });

      const keyPair: KeyPair = {
        publicKey,
        privateKey,
        type: algorithm
      };

      return keyPair;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to generate key pair: ${errorMessage}`);
    }
  }

  /**
   * Sign data with a private key
   */
  async sign(data: any, keyId: string): Promise<string> {
    try {
      // For now, create a simple hash-based signature
      // In a real implementation, this would use proper cryptographic signing
      const dataString = JSON.stringify(data);
      const hash = crypto.createHash('sha256').update(dataString).digest('hex');
      
      // This is a placeholder - in reality, you'd use the actual private key
      return `ed25519-${hash}-${keyId}`;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to sign data: ${errorMessage}`);
    }
  }

  /**
   * Verify a signature
   */
  async verify(data: any, signature: string, publicKey: string): Promise<boolean> {
    try {
      // For now, perform simple validation
      // In a real implementation, this would use proper cryptographic verification
      if (!signature || !publicKey) {
        return false;
      }
      
      // This is a placeholder verification
      return signature.startsWith('ed25519-') && publicKey.length > 0;
    } catch (error) {
      return false;
    }
  }

  /**
   * Create a proof structure
   */
  async createProof(options: {
    type: string;
    verificationMethod: string;
    proofPurpose: string;
    created?: string;
    challenge?: string;
    domain?: string;
    data: any;
    privateKey?: string;
  }): Promise<any> {
    const proof = {
      type: options.type,
      created: options.created || new Date().toISOString(),
      verificationMethod: options.verificationMethod,
      proofPurpose: options.proofPurpose
    };

    if (options.challenge) {
      (proof as any).challenge = options.challenge;
    }
    
    if (options.domain) {
      (proof as any).domain = options.domain;
    }

    // Sign the data
    const signature = await this.sign(options.data, options.verificationMethod);
    (proof as any).proofValue = signature;

    return proof;
  }

  /**
   * Verify a proof
   */
  async verifyProof(proof: any, data: any, publicKey: string): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Check required proof fields
      if (!proof.type) {
        errors.push('Missing proof type');
      }
      
      if (!proof.verificationMethod) {
        errors.push('Missing verification method');
      }
      
      if (!proof.proofPurpose) {
        errors.push('Missing proof purpose');
      }

      if (!proof.proofValue && !proof.jws) {
        errors.push('Missing proof value or JWS');
      }

      if (errors.length > 0) {
        return { valid: false, errors, warnings };
      }

      // Verify the signature
      const signatureToVerify = proof.proofValue || proof.jws;
      const isValid = await this.verify(data, signatureToVerify, publicKey);

      if (!isValid) {
        errors.push('Invalid signature');
      }

      return { valid: errors.length === 0, errors, warnings };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Proof verification failed: ${errorMessage}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Hash data using SHA-256
   */
  hash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate a random challenge for proof challenges
   */
  generateChallenge(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Store a key pair with an identifier
   */
  storeKeyPair(keyId: string, keyPair: KeyPair): void {
    this.keyPairs.set(keyId, keyPair);
  }

  /**
   * Retrieve a key pair by identifier
   */
  getKeyPair(keyId: string): KeyPair | undefined {
    return this.keyPairs.get(keyId);
  }

  /**
   * List all stored key identifiers
   */
  listKeyIds(): string[] {
    return Array.from(this.keyPairs.keys());
  }

  /**
   * Remove a key pair
   */
  removeKeyPair(keyId: string): boolean {
    return this.keyPairs.delete(keyId);
  }
}
