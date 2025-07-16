/**
 * Security and cryptographic operations for Verifiable Credentials
 * Handles signing, verification, and key management
 */
import { ValidationResult } from '../types';
export interface KeyPair {
    publicKey: string;
    privateKey: string;
    type: string;
}
export declare class SecurityManager {
    private keyPairs;
    /**
     * Generate a new key pair
     */
    generateKeyPair(algorithm?: string): KeyPair;
    /**
     * Sign data with a private key
     */
    sign(data: any, keyId: string): Promise<string>;
    /**
     * Verify a signature
     */
    verify(data: any, signature: string, publicKey: string): Promise<boolean>;
    /**
     * Create a proof structure
     */
    createProof(options: {
        type: string;
        verificationMethod: string;
        proofPurpose: string;
        created?: string;
        challenge?: string;
        domain?: string;
        data: any;
        privateKey?: string;
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
     * Generate a random challenge for proof challenges
     */
    generateChallenge(): string;
    /**
     * Store a key pair with an identifier
     */
    storeKeyPair(keyId: string, keyPair: KeyPair): void;
    /**
     * Retrieve a key pair by identifier
     */
    getKeyPair(keyId: string): KeyPair | undefined;
    /**
     * List all stored key identifiers
     */
    listKeyIds(): string[];
    /**
     * Remove a key pair
     */
    removeKeyPair(keyId: string): boolean;
}
//# sourceMappingURL=index.d.ts.map