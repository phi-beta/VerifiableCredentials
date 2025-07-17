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
exports.SecurityManager = exports.JsonWebSignature2020Suite = exports.Ed25519Signature2020Suite = exports.CryptographicSuite = void 0;
const crypto = __importStar(require("crypto"));
// Dynamic imports for ES modules
let ed25519;
let secp256k1;
let jose;
async function loadCryptoModules() {
    if (!ed25519) {
        ed25519 = await Promise.resolve().then(() => __importStar(require('@noble/ed25519')));
    }
    if (!secp256k1) {
        secp256k1 = await Promise.resolve().then(() => __importStar(require('@noble/secp256k1')));
    }
    if (!jose) {
        jose = await Promise.resolve().then(() => __importStar(require('jose')));
    }
}
class CryptographicSuite {
    constructor(type, keyType) {
        this.type = type;
        this.keyType = keyType;
    }
    async sign(data, privateKey) {
        throw new Error('Sign method must be implemented by concrete suite');
    }
    async verify(data, signature, publicKey) {
        throw new Error('Verify method must be implemented by concrete suite');
    }
    async createProof(data, options, privateKey) {
        throw new Error('CreateProof method must be implemented by concrete suite');
    }
    async verifyProof(proof, data, publicKey) {
        throw new Error('VerifyProof method must be implemented by concrete suite');
    }
}
exports.CryptographicSuite = CryptographicSuite;
class Ed25519Signature2020Suite extends CryptographicSuite {
    constructor() {
        super('Ed25519Signature2020', 'Ed25519');
    }
    async sign(data, privateKey) {
        try {
            // Use native crypto for Ed25519 signing (no digest algorithm needed for Ed25519)
            const keyObject = crypto.createPrivateKey(privateKey);
            const signature = crypto.sign(null, data, keyObject);
            return new Uint8Array(signature);
        }
        catch (error) {
            throw new Error(`Ed25519 signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    async verify(data, signature, publicKey) {
        try {
            // Use native crypto for Ed25519 verification (no digest algorithm needed for Ed25519)
            const keyObject = crypto.createPublicKey(publicKey);
            return crypto.verify(null, data, keyObject, signature);
        }
        catch (error) {
            return false;
        }
    }
    async createProof(data, options, privateKey) {
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
    async verifyProof(proof, data, publicKey) {
        try {
            const canonicalData = this.canonicalize(data);
            const dataBytes = new TextEncoder().encode(canonicalData);
            const signature = this.base64urlToBytes(proof.proofValue);
            return await this.verify(dataBytes, signature, publicKey);
        }
        catch (error) {
            return false;
        }
    }
    pemToBytes(pem) {
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
    bytesToBase64url(bytes) {
        const base64 = btoa(String.fromCharCode(...bytes));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    base64urlToBytes(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    canonicalize(data) {
        // Simple JSON canonicalization - in production, use RDFC-1.0
        return JSON.stringify(data, Object.keys(data).sort());
    }
}
exports.Ed25519Signature2020Suite = Ed25519Signature2020Suite;
class JsonWebSignature2020Suite extends CryptographicSuite {
    constructor() {
        super('JsonWebSignature2020', 'Ed25519');
    }
    async createProof(data, options, privateKey) {
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
        }
        catch (error) {
            throw new Error(`JWS creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    async verifyProof(proof, data, publicKey) {
        try {
            // Simple JWT verification using native crypto
            const jwtParts = proof.jws.split('.');
            if (jwtParts.length !== 3)
                return false;
            const header = JSON.parse(Buffer.from(jwtParts[0], 'base64url').toString());
            const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString());
            const signature = Buffer.from(jwtParts[2], 'base64url');
            // Verify the payload contains the expected data
            const payloadMatches = JSON.stringify(payload.vc) === JSON.stringify(data);
            // Verify the signature
            const keyObject = crypto.createPublicKey(publicKey);
            const signatureValid = crypto.verify('sha256', Buffer.from(jwtParts[1]), keyObject, signature);
            return payloadMatches && signatureValid;
        }
        catch (error) {
            return false;
        }
    }
}
exports.JsonWebSignature2020Suite = JsonWebSignature2020Suite;
class SecurityManager {
    constructor() {
        this.keyPairs = new Map();
        this.suites = new Map();
        // Register cryptographic suites
        this.suites.set('Ed25519Signature2020', new Ed25519Signature2020Suite());
        this.suites.set('JsonWebSignature2020', new JsonWebSignature2020Suite());
    }
    /**
     * Generate a new key pair
     */
    async generateKeyPair(keyType = 'Ed25519', keyId) {
        try {
            let publicKey;
            let privateKey;
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
            const keyPair = {
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
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to generate key pair: ${errorMessage}`);
        }
    }
    /**
     * Sign data with a private key using the specified proof type
     */
    async sign(data, keyId, proofType = 'Ed25519Signature2020') {
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
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to sign data: ${errorMessage}`);
        }
    }
    /**
     * Verify a signature
     */
    async verify(data, signature, publicKey, proofType = 'Ed25519Signature2020') {
        try {
            const suite = this.suites.get(proofType);
            if (!suite) {
                return false;
            }
            const canonicalData = this.canonicalize(data);
            const dataBytes = new TextEncoder().encode(canonicalData);
            const signatureBytes = this.base64urlToBytes(signature);
            return await suite.verify(dataBytes, signatureBytes, publicKey);
        }
        catch (error) {
            return false;
        }
    }
    /**
     * Create a proof structure
     */
    async createProof(options) {
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
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to create proof: ${errorMessage}`);
        }
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
            // Get the appropriate cryptographic suite
            const suite = this.suites.get(proof.type);
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
     * Generate a secure random challenge
     */
    generateChallenge() {
        return crypto.randomBytes(32).toString('hex');
    }
    /**
     * Generate a secure nonce
     */
    generateNonce() {
        return crypto.randomBytes(16).toString('hex');
    }
    /**
     * Derive a key from a passphrase using PBKDF2
     */
    deriveKey(passphrase, salt, iterations = 100000) {
        return crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256').toString('hex');
    }
    /**
     * Encrypt data using AES-256-GCM
     */
    encrypt(data, key) {
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
    decrypt(encryptedData, key) {
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
     * Get public key for a stored key pair
     */
    getPublicKey(keyId) {
        const keyPair = this.keyPairs.get(keyId);
        return keyPair?.publicKey;
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
    /**
     * Create a DID document key reference
     */
    createDidKeyReference(did, keyId) {
        return `${did}#${keyId}`;
    }
    /**
     * Resolve a verification method to a public key
     */
    async resolveVerificationMethod(verificationMethod) {
        // This is a placeholder - in a real implementation, this would resolve
        // the verification method using a DID resolver
        const keyPair = this.keyPairs.get(verificationMethod);
        return keyPair?.publicKey || null;
    }
    // Helper methods
    canonicalize(data) {
        // Simple JSON canonicalization - in production, use RDFC-1.0
        const sortedData = this.sortObjectRecursively(data);
        return JSON.stringify(sortedData);
    }
    sortObjectRecursively(obj) {
        if (Array.isArray(obj)) {
            return obj.map(item => this.sortObjectRecursively(item));
        }
        else if (obj !== null && typeof obj === 'object') {
            const sorted = {};
            Object.keys(obj).sort().forEach(key => {
                sorted[key] = this.sortObjectRecursively(obj[key]);
            });
            return sorted;
        }
        return obj;
    }
    bytesToBase64url(bytes) {
        const base64 = btoa(String.fromCharCode(...bytes));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    base64urlToBytes(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    bytesToPem(bytes, type) {
        const base64 = btoa(String.fromCharCode(...bytes));
        const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;
        return `-----BEGIN ${type}-----\n${formatted}\n-----END ${type}-----`;
    }
}
exports.SecurityManager = SecurityManager;
exports.default = SecurityManager;
//# sourceMappingURL=index.js.map