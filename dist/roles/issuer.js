"use strict";
/**
 * Issuer implementation for W3C Verifiable Credentials
 * Handles credential issuance and signing
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.Issuer = void 0;
const uuid_1 = require("uuid");
const context_1 = require("../context");
const security_1 = require("../security");
class Issuer {
    constructor(options) {
        this.issuerInfo = {
            id: options.id,
            name: options.name,
            description: options.description,
            url: options.url,
            image: options.image
        };
        this.securityManager = new security_1.SecurityManager();
    }
    /**
     * Issue a new verifiable credential
     */
    async issueCredential(options) {
        const now = new Date().toISOString();
        const credentialId = options.id || `urn:uuid:${(0, uuid_1.v4)()}`;
        // Build the context array
        const contextArray = [context_1.W3C_VC_CONTEXT_V2];
        if (options.context) {
            if (Array.isArray(options.context)) {
                contextArray.push(...options.context);
            }
            else {
                contextArray.push(options.context);
            }
        }
        // Build the type array
        const typeArray = ['VerifiableCredential'];
        if (options.type) {
            if (Array.isArray(options.type)) {
                typeArray.push(...options.type);
            }
            else {
                typeArray.push(options.type);
            }
        }
        // Create the unsigned credential
        const credential = {
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
    async signCredential(credential) {
        try {
            // For now, create a simple proof structure
            // In a real implementation, this would use proper cryptographic signing
            const proof = {
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
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to sign credential: ${errorMessage}`);
        }
    }
    /**
     * Revoke a credential (update its status)
     */
    async revokeCredential(credentialId, reason) {
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
    getIssuerInfo() {
        return { ...this.issuerInfo };
    }
    /**
     * Update issuer information
     */
    updateIssuerInfo(updates) {
        this.issuerInfo = {
            ...this.issuerInfo,
            ...updates
        };
    }
    /**
     * Batch issue multiple credentials
     */
    async batchIssueCredentials(credentials) {
        const issuedCredentials = [];
        for (const credentialOptions of credentials) {
            try {
                const credential = await this.issueCredential(credentialOptions);
                issuedCredentials.push(credential);
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                throw new Error(`Failed to issue credential in batch: ${errorMessage}`);
            }
        }
        return issuedCredentials;
    }
}
exports.Issuer = Issuer;
//# sourceMappingURL=issuer.js.map