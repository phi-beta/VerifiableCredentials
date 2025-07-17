/**
 * Security and cryptographic operations for Verifiable Credentials
 * Handles signing, verification, and key management
 */

import * as crypto from 'crypto';
import * as CryptoJS from 'crypto-js';
import { ValidationResult } from '../types';

// Dynamic imports for ES modules
let ed25519: any;
let secp256k1: any;
let jose: any;

async function loadCryptoModules() {
  if (!ed25519) {
    ed25519 = await import('@noble/ed25519');
  }
  if (!secp256k1) {
    secp256k1 = await import('@noble/secp256k1');
  }
  if (!jose) {
    jose = await import('jose');
  }
}

export type KeyType = 'Ed25519' | 'secp256k1' | 'RSA' | 'ES256K';
export type ProofType = 'Ed25519Signature2020' | 'EcdsaSecp256k1Signature2019' | 'JsonWebSignature2020' | 'DataIntegrityProof';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
  type: KeyType;
  id?: string;
  controller?: string;
}

export interface DigitalSignature {
  signature: string;
  algorithm: string;
  publicKey: string;
}

export interface ProofOptions {
  type: ProofType;
  verificationMethod: string;
  proofPurpose: string;
  created?: string;
  challenge?: string;
  domain?: string;
}

export class CryptographicSuite {
  constructor(
    public readonly type: ProofType,
    public readonly keyType: KeyType
  ) {}

  async sign(data: Uint8Array, privateKey: string): Promise<Uint8Array> {
    throw new Error('Sign method must be implemented by concrete suite');
  }

  async verify(data: Uint8Array, signature: Uint8Array, publicKey: string): Promise<boolean> {
    throw new Error('Verify method must be implemented by concrete suite');
  }

  async createProof(data: any, options: ProofOptions, privateKey: string): Promise<any> {
    throw new Error('CreateProof method must be implemented by concrete suite');
  }

  async verifyProof(proof: any, data: any, publicKey: string): Promise<boolean> {
    throw new Error('VerifyProof method must be implemented by concrete suite');
  }
}

export class Ed25519Signature2020Suite extends CryptographicSuite {
  constructor() {
    super('Ed25519Signature2020', 'Ed25519');
  }

  async sign(data: Uint8Array, privateKey: string): Promise<Uint8Array> {
    try {
      // Use native crypto for Ed25519 signing (no digest algorithm needed for Ed25519)
      const keyObject = crypto.createPrivateKey(privateKey);
      const signature = crypto.sign(null, data, keyObject);
      return new Uint8Array(signature);
    } catch (error) {
      throw new Error(`Ed25519 signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async verify(data: Uint8Array, signature: Uint8Array, publicKey: string): Promise<boolean> {
    try {
      // Use native crypto for Ed25519 verification (no digest algorithm needed for Ed25519)
      const keyObject = crypto.createPublicKey(publicKey);
      return crypto.verify(null, data, keyObject, signature);
    } catch (error) {
      return false;
    }
  }

  async createProof(data: any, options: ProofOptions, privateKey: string): Promise<any> {
    const canonicalData = this.canonicalize(data);
    const dataBytes = new TextEncoder().encode(canonicalData);
    const signature = await this.sign(dataBytes, privateKey);

    return {
      type: this.type,
      created: options.created || new Date().toISOString(),
      verificationMethod: options.verificationMethod,
      proofPurpose: options.proofPurpose,
      ...(options.challenge && { challenge: options.challenge }),
      ...(options.domain && { domain: options.domain }),
      proofValue: this.bytesToBase64url(signature)
    };
  }

  async verifyProof(proof: any, data: any, publicKey: string): Promise<boolean> {
    try {
      const canonicalData = this.canonicalize(data);
      const dataBytes = new TextEncoder().encode(canonicalData);
      const signature = this.base64urlToBytes(proof.proofValue);
      
      return await this.verify(dataBytes, signature, publicKey);
    } catch (error) {
      return false;
    }
  }

  private pemToBytes(pem: string): Uint8Array {
    // Simple PEM parsing - in production, use a proper ASN.1 parser
    const base64 = pem
      .replace(/-----BEGIN [^-]+-----/, '')
      .replace(/-----END [^-]+-----/, '')
      .replace(/\s/g, '');
    
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    
    // For Ed25519, extract the 32-byte private key from the PKCS#8 structure
    // This is a simplified extraction - in production, use proper ASN.1 parsing
    if (bytes.length > 32) {
      return bytes.slice(-32); // Take last 32 bytes for Ed25519
    }
    return bytes;
  }

  private bytesToBase64url(bytes: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private base64urlToBytes(base64url: string): Uint8Array {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private canonicalize(data: any): string {
    // Simple JSON canonicalization - in production, use RDFC-1.0
    return JSON.stringify(data, Object.keys(data).sort());
  }
}

export class JsonWebSignature2020Suite extends CryptographicSuite {
  constructor() {
    super('JsonWebSignature2020', 'Ed25519');
  }

  async createProof(data: any, options: ProofOptions, privateKey: string): Promise<any> {
    try {
      // Simple implementation without full JWT for demonstration
      const payload = {
        vc: data,
        iss: options.verificationMethod,
        aud: options.domain || 'https://example.com',
        iat: Math.floor(Date.now() / 1000),
        ...(options.challenge && { nonce: options.challenge })
      };

      // Create a simple signature using native crypto
      const keyObject = crypto.createPrivateKey(privateKey);
      const payloadString = JSON.stringify(payload);
      const signature = crypto.sign('sha256', Buffer.from(payloadString), keyObject);
      const jws = `${Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url')}.${Buffer.from(payloadString).toString('base64url')}.${signature.toString('base64url')}`;

      return {
        type: this.type,
        created: options.created || new Date().toISOString(),
        verificationMethod: options.verificationMethod,
        proofPurpose: options.proofPurpose,
        ...(options.challenge && { challenge: options.challenge }),
        ...(options.domain && { domain: options.domain }),
        jws: jws
      };
    } catch (error) {
      throw new Error(`JWS creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async verifyProof(proof: any, data: any, publicKey: string): Promise<boolean> {
    try {
      // Simple JWT verification using native crypto
      const jwtParts = proof.jws.split('.');
      if (jwtParts.length !== 3) return false;

      const header = JSON.parse(Buffer.from(jwtParts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString());
      const signature = Buffer.from(jwtParts[2], 'base64url');

      // Verify the payload contains the expected data
      const payloadMatches = JSON.stringify(payload.vc) === JSON.stringify(data);
      
      // Verify the signature
      const keyObject = crypto.createPublicKey(publicKey);
      const signatureValid = crypto.verify('sha256', Buffer.from(jwtParts[1]), keyObject, signature);
      
      return payloadMatches && signatureValid;
    } catch (error) {
      return false;
    }
  }
}

export class SecurityManager {
  private keyPairs: Map<string, KeyPair> = new Map();
  private suites: Map<ProofType, CryptographicSuite> = new Map();

  constructor() {
    // Register cryptographic suites
    this.suites.set('Ed25519Signature2020', new Ed25519Signature2020Suite());
    this.suites.set('JsonWebSignature2020', new JsonWebSignature2020Suite());
  }

  /**
   * Generate a new key pair
   */
  async generateKeyPair(keyType: KeyType = 'Ed25519', keyId?: string): Promise<KeyPair> {
    try {
      let publicKey: string;
      let privateKey: string;

      switch (keyType) {
        case 'Ed25519':
          const ed25519Keys = crypto.generateKeyPairSync('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
          });
          publicKey = ed25519Keys.publicKey;
          privateKey = ed25519Keys.privateKey;
          break;

        case 'secp256k1':
        case 'ES256K':
          // Use secp256k1 curve with native crypto
          const secp256k1Keys = crypto.generateKeyPairSync('ec', {
            namedCurve: 'secp256k1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
          });
          publicKey = secp256k1Keys.publicKey;
          privateKey = secp256k1Keys.privateKey;
          break;

        case 'RSA':
          const rsaKeys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
          });
          publicKey = rsaKeys.publicKey;
          privateKey = rsaKeys.privateKey;
          break;

        default:
          throw new Error(`Unsupported key type: ${keyType}`);
      }

      const keyPair: KeyPair = {
        publicKey,
        privateKey,
        type: keyType,
        id: keyId,
      };

      // Store the key pair if an ID is provided
      if (keyId) {
        this.keyPairs.set(keyId, keyPair);
      }

      return keyPair;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to generate key pair: ${errorMessage}`);
    }
  }

  /**
   * Sign data with a private key using the specified proof type
   */
  async sign(data: any, keyId: string, proofType: ProofType = 'Ed25519Signature2020'): Promise<string> {
    try {
      const keyPair = this.keyPairs.get(keyId);
      if (!keyPair) {
        throw new Error(`Key pair not found: ${keyId}`);
      }

      const suite = this.suites.get(proofType);
      if (!suite) {
        throw new Error(`Unsupported proof type: ${proofType}`);
      }

      const canonicalData = this.canonicalize(data);
      const dataBytes = new TextEncoder().encode(canonicalData);
      const signature = await suite.sign(dataBytes, keyPair.privateKey);
      
      return this.bytesToBase64url(signature);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to sign data: ${errorMessage}`);
    }
  }

  /**
   * Verify a signature
   */
  async verify(data: any, signature: string, publicKey: string, proofType: ProofType = 'Ed25519Signature2020'): Promise<boolean> {
    try {
      const suite = this.suites.get(proofType);
      if (!suite) {
        return false;
      }

      const canonicalData = this.canonicalize(data);
      const dataBytes = new TextEncoder().encode(canonicalData);
      const signatureBytes = this.base64urlToBytes(signature);
      
      return await suite.verify(dataBytes, signatureBytes, publicKey);
    } catch (error) {
      return false;
    }
  }

  /**
   * Create a proof structure
   */
  async createProof(options: ProofOptions & {
    data: any;
    keyId: string;
  }): Promise<any> {
    try {
      const keyPair = this.keyPairs.get(options.keyId);
      if (!keyPair) {
        throw new Error(`Key pair not found: ${options.keyId}`);
      }

      const suite = this.suites.get(options.type);
      if (!suite) {
        throw new Error(`Unsupported proof type: ${options.type}`);
      }

      return await suite.createProof(options.data, options, keyPair.privateKey);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to create proof: ${errorMessage}`);
    }
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

      // Get the appropriate cryptographic suite
      const suite = this.suites.get(proof.type as ProofType);
      if (!suite) {
        errors.push(`Unsupported proof type: ${proof.type}`);
        return { valid: false, errors, warnings };
      }

      // Verify the proof
      const isValid = await suite.verifyProof(proof, data, publicKey);

      if (!isValid) {
        errors.push('Invalid cryptographic signature');
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
   * Generate a secure random challenge
   */
  generateChallenge(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Generate a secure nonce
   */
  generateNonce(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Derive a key from a passphrase using PBKDF2
   */
  deriveKey(passphrase: string, salt: string, iterations: number = 100000): string {
    return crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256').toString('hex');
  }

  /**
   * Encrypt data using AES-256-GCM
   */
  encrypt(data: string, key: string): { encrypted: string; iv: string; tag: string } {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex')
    };
  }

  /**
   * Decrypt data using AES-256-GCM
   */
  decrypt(encryptedData: { encrypted: string; iv: string; tag: string }, key: string): string {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
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
   * Get public key for a stored key pair
   */
  getPublicKey(keyId: string): string | undefined {
    const keyPair = this.keyPairs.get(keyId);
    return keyPair?.publicKey;
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

  /**
   * Create a DID document key reference
   */
  createDidKeyReference(did: string, keyId: string): string {
    return `${did}#${keyId}`;
  }

  /**
   * Resolve a verification method to a public key
   */
  async resolveVerificationMethod(verificationMethod: string): Promise<string | null> {
    // This is a placeholder - in a real implementation, this would resolve
    // the verification method using a DID resolver
    const keyPair = this.keyPairs.get(verificationMethod);
    return keyPair?.publicKey || null;
  }

  // Helper methods
  private canonicalize(data: any): string {
    // Simple JSON canonicalization - in production, use RDFC-1.0
    const sortedData = this.sortObjectRecursively(data);
    return JSON.stringify(sortedData);
  }

  private sortObjectRecursively(obj: any): any {
    if (Array.isArray(obj)) {
      return obj.map(item => this.sortObjectRecursively(item));
    } else if (obj !== null && typeof obj === 'object') {
      const sorted: any = {};
      Object.keys(obj).sort().forEach(key => {
        sorted[key] = this.sortObjectRecursively(obj[key]);
      });
      return sorted;
    }
    return obj;
  }

  private bytesToBase64url(bytes: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private base64urlToBytes(base64url: string): Uint8Array {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private bytesToPem(bytes: Uint8Array, type: string): string {
    const base64 = btoa(String.fromCharCode(...bytes));
    const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;
    return `-----BEGIN ${type}-----\n${formatted}\n-----END ${type}-----`;
  }
}

export default SecurityManager;
