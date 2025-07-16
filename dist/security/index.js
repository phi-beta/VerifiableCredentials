"use strict";
/**
 * Security and cryptographic operations for Verifiable Credentials
 * Handles signing, verification, and key management
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityManager = void 0;
const crypto = __importStar(require("crypto"));
class SecurityManager {
    constructor() {
        this.keyPairs = new Map();
    }
    /**
     * Generate a new key pair
     */
    generateKeyPair(algorithm = 'ed25519') {
        try {
            const { publicKey, privateKey } = crypto.generateKeyPairSync(algorithm, {
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            });
            const keyPair = {
                publicKey,
                privateKey,
                type: algorithm
            };
            return keyPair;
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to generate key pair: ${errorMessage}`);
        }
    }
    /**
     * Sign data with a private key
     */
    async sign(data, keyId) {
        try {
            // For now, create a simple hash-based signature
            // In a real implementation, this would use proper cryptographic signing
            const dataString = JSON.stringify(data);
            const hash = crypto.createHash('sha256').update(dataString).digest('hex');
            // This is a placeholder - in reality, you'd use the actual private key
            return `ed25519-${hash}-${keyId}`;
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to sign data: ${errorMessage}`);
        }
    }
    /**
     * Verify a signature
     */
    async verify(data, signature, publicKey) {
        try {
            // For now, perform simple validation
            // In a real implementation, this would use proper cryptographic verification
            if (!signature || !publicKey) {
                return false;
            }
            // This is a placeholder verification
            return signature.startsWith('ed25519-') && publicKey.length > 0;
        }
        catch (error) {
            return false;
        }
    }
    /**
     * Create a proof structure
     */
    async createProof(options) {
        const proof = {
            type: options.type,
            created: options.created || new Date().toISOString(),
            verificationMethod: options.verificationMethod,
            proofPurpose: options.proofPurpose
        };
        if (options.challenge) {
            proof.challenge = options.challenge;
        }
        if (options.domain) {
            proof.domain = options.domain;
        }
        // Sign the data
        const signature = await this.sign(options.data, options.verificationMethod);
        proof.proofValue = signature;
        return proof;
    }
    /**
     * Verify a proof
     */
    async verifyProof(proof, data, publicKey) {
        const errors = [];
        const warnings = [];
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
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Proof verification failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
    /**
     * Hash data using SHA-256
     */
    hash(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }
    /**
     * Generate a random challenge for proof challenges
     */
    generateChallenge() {
        return crypto.randomBytes(32).toString('hex');
    }
    /**
     * Store a key pair with an identifier
     */
    storeKeyPair(keyId, keyPair) {
        this.keyPairs.set(keyId, keyPair);
    }
    /**
     * Retrieve a key pair by identifier
     */
    getKeyPair(keyId) {
        return this.keyPairs.get(keyId);
    }
    /**
     * List all stored key identifiers
     */
    listKeyIds() {
        return Array.from(this.keyPairs.keys());
    }
    /**
     * Remove a key pair
     */
    removeKeyPair(keyId) {
        return this.keyPairs.delete(keyId);
    }
}
exports.SecurityManager = SecurityManager;
//# sourceMappingURL=index.js.map