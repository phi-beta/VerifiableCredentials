/**
 * Security and cryptographic operations for Verifiable Credentials
 * Handles signing, verification, and key management
 */
import { ValidationResult } from '../types';
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
export declare class CryptographicSuite {
    readonly type: ProofType;
    readonly keyType: KeyType;
    constructor(type: ProofType, keyType: KeyType);
    sign(data: Uint8Array, privateKey: string): Promise<Uint8Array>;
    verify(data: Uint8Array, signature: Uint8Array, publicKey: string): Promise<boolean>;
    createProof(data: any, options: ProofOptions, privateKey: string): Promise<any>;
    verifyProof(proof: any, data: any, publicKey: string): Promise<boolean>;
}
export declare class Ed25519Signature2020Suite extends CryptographicSuite {
    constructor();
    sign(data: Uint8Array, privateKey: string): Promise<Uint8Array>;
    verify(data: Uint8Array, signature: Uint8Array, publicKey: string): Promise<boolean>;
    createProof(data: any, options: ProofOptions, privateKey: string): Promise<any>;
    verifyProof(proof: any, data: any, publicKey: string): Promise<boolean>;
    private pemToBytes;
    private bytesToBase64url;
    private base64urlToBytes;
    private canonicalize;
}
export declare class JsonWebSignature2020Suite extends CryptographicSuite {
    constructor();
    createProof(data: any, options: ProofOptions, privateKey: string): Promise<any>;
    verifyProof(proof: any, data: any, publicKey: string): Promise<boolean>;
}
export declare class SecurityManager {
    private keyPairs;
    private suites;
    constructor();
    /**
     * Generate a new key pair
     */
    generateKeyPair(keyType?: KeyType, keyId?: string): Promise<KeyPair>;
    /**
     * Sign data with a private key using the specified proof type
     */
    sign(data: any, keyId: string, proofType?: ProofType): Promise<string>;
    /**
     * Verify a signature
     */
    verify(data: any, signature: string, publicKey: string, proofType?: ProofType): Promise<boolean>;
    /**
     * Create a proof structure
     */
    createProof(options: ProofOptions & {
        data: any;
        keyId: string;
    }): Promise<any>;
    /**
     * Verify a proof
     */
    verifyProof(proof: any, data: any, publicKey: string): Promise<ValidationResult>;
    /**
     * Hash data using SHA-256
     */
    hash(data: string): string;
    /**
     * Generate a secure random challenge
     */
    generateChallenge(): string;
    /**
     * Generate a secure nonce
     */
    generateNonce(): string;
    /**
     * Derive a key from a passphrase using PBKDF2
     */
    deriveKey(passphrase: string, salt: string, iterations?: number): string;
    /**
     * Encrypt data using AES-256-GCM
     */
    encrypt(data: string, key: string): {
        encrypted: string;
        iv: string;
        tag: string;
    };
    /**
     * Decrypt data using AES-256-GCM
     */
    decrypt(encryptedData: {
        encrypted: string;
        iv: string;
        tag: string;
    }, key: string): string;
    /**
     * Store a key pair with an identifier
     */
    storeKeyPair(keyId: string, keyPair: KeyPair): void;
    /**
     * Retrieve a key pair by identifier
     */
    getKeyPair(keyId: string): KeyPair | undefined;
    /**
     * Get public key for a stored key pair
     */
    getPublicKey(keyId: string): string | undefined;
    /**
     * List all stored key identifiers
     */
    listKeyIds(): string[];
    /**
     * Remove a key pair
     */
    removeKeyPair(keyId: string): boolean;
    /**
     * Create a DID document key reference
     */
    createDidKeyReference(did: string, keyId: string): string;
    /**
     * Resolve a verification method to a public key
     */
    resolveVerificationMethod(verificationMethod: string): Promise<string | null>;
    private canonicalize;
    private sortObjectRecursively;
    private bytesToBase64url;
    private base64urlToBytes;
    private bytesToPem;
}
export default SecurityManager;
//# sourceMappingURL=index.d.ts.map