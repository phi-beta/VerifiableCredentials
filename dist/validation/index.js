"use strict";
/**
 * Comprehensive validation algorithms for Verifiable Credentials
 * Implements W3C validation requirements and algorithms
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ValidationEngine = void 0;
const context_1 = require("../context");
const security_1 = require("../security");
class ValidationEngine {
    constructor() {
        this.contextManager = new context_1.ContextManager();
        this.securityManager = new security_1.SecurityManager();
    }
    /**
     * Comprehensive credential validation
     */
    async validateCredential(credential, options = {}) {
        const errors = [];
        const warnings = [];
        try {
            // 1. JSON-LD Context validation
            const contextResult = await this.contextManager.validateContext(credential);
            if (!contextResult.valid) {
                errors.push(...contextResult.errors);
                warnings.push(...(contextResult.warnings || []));
            }
            // 2. Structure validation
            const structureResult = this.validateCredentialStructure(credential, options);
            if (!structureResult.valid) {
                errors.push(...structureResult.errors);
                warnings.push(...(structureResult.warnings || []));
            }
            // 3. Type validation
            const typeResult = this.validateCredentialType(credential, options.allowedTypes);
            if (!typeResult.valid) {
                errors.push(...typeResult.errors);
                warnings.push(...(typeResult.warnings || []));
            }
            // 4. Issuer validation
            const issuerResult = this.validateIssuer(credential, options.trustedIssuers);
            if (!issuerResult.valid) {
                errors.push(...issuerResult.errors);
                warnings.push(...(issuerResult.warnings || []));
            }
            // 5. Temporal validation (expiration)
            if (options.validateExpiration !== false) {
                const temporalResult = this.validateTemporalConstraints(credential);
                if (!temporalResult.valid) {
                    errors.push(...temporalResult.errors);
                    warnings.push(...(temporalResult.warnings || []));
                }
            }
            // 6. Proof validation
            if (options.validateProof !== false && credential.proof) {
                const proofResult = await this.validateCredentialProof(credential);
                if (!proofResult.valid) {
                    errors.push(...proofResult.errors);
                    warnings.push(...(proofResult.warnings || []));
                }
            }
            // 7. Schema validation
            if (options.validateSchema && credential.credentialSchema) {
                const schemaResult = await this.validateCredentialSchema(credential);
                if (!schemaResult.valid) {
                    errors.push(...schemaResult.errors);
                    warnings.push(...(schemaResult.warnings || []));
                }
            }
            // 8. Revocation validation
            if (options.validateRevocation && credential.credentialStatus) {
                const revocationResult = await this.validateRevocationStatus(credential);
                if (!revocationResult.valid) {
                    errors.push(...revocationResult.errors);
                    warnings.push(...(revocationResult.warnings || []));
                }
            }
            // 9. Required fields validation
            if (options.requiredFields) {
                const fieldsResult = this.validateRequiredFields(credential, options.requiredFields);
                if (!fieldsResult.valid) {
                    errors.push(...fieldsResult.errors);
                    warnings.push(...(fieldsResult.warnings || []));
                }
            }
            return { valid: errors.length === 0, errors, warnings };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Validation failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
    /**
     * Comprehensive presentation validation
     */
    async validatePresentation(presentation, options = {}) {
        const errors = [];
        const warnings = [];
        try {
            // 1. JSON-LD Context validation
            const contextResult = await this.contextManager.validateContext(presentation);
            if (!contextResult.valid) {
                errors.push(...contextResult.errors);
                warnings.push(...(contextResult.warnings || []));
            }
            // 2. Structure validation
            const structureResult = this.validatePresentationStructure(presentation);
            if (!structureResult.valid) {
                errors.push(...structureResult.errors);
                warnings.push(...(structureResult.warnings || []));
            }
            // 3. Proof validation
            if (options.validateProof !== false && presentation.proof) {
                const proofResult = await this.validatePresentationProof(presentation);
                if (!proofResult.valid) {
                    errors.push(...proofResult.errors);
                    warnings.push(...(proofResult.warnings || []));
                }
            }
            // 4. Validate embedded credentials
            if (presentation.verifiableCredential) {
                for (let i = 0; i < presentation.verifiableCredential.length; i++) {
                    const credential = presentation.verifiableCredential[i];
                    const credentialResult = await this.validateCredential(credential, options);
                    if (!credentialResult.valid) {
                        errors.push(...credentialResult.errors.map(err => `Credential ${i}: ${err}`));
                    }
                    if (credentialResult.warnings) {
                        warnings.push(...credentialResult.warnings.map(warn => `Credential ${i}: ${warn}`));
                    }
                }
            }
            return { valid: errors.length === 0, errors, warnings };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Presentation validation failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
    /**
     * Validate credential structure
     */
    validateCredentialStructure(credential, options) {
        const errors = [];
        const warnings = [];
        // Required fields per W3C spec
        const requiredFields = ['@context', 'type', 'issuer', 'credentialSubject'];
        for (const field of requiredFields) {
            if (!credential[field]) {
                errors.push(`Missing required field: ${field}`);
            }
        }
        // Validate @context structure
        if (credential['@context']) {
            const contexts = Array.isArray(credential['@context'])
                ? credential['@context']
                : [credential['@context']];
            if (contexts.length === 0) {
                errors.push('@context cannot be empty');
            }
        }
        // Validate type structure
        if (credential.type) {
            const types = Array.isArray(credential.type) ? credential.type : [credential.type];
            if (!types.includes('VerifiableCredential')) {
                errors.push('Type must include VerifiableCredential');
            }
        }
        // Validate issuer structure
        if (credential.issuer) {
            if (typeof credential.issuer === 'object' && !credential.issuer.id) {
                errors.push('Issuer object must have an id field');
            }
        }
        // Validate credentialSubject structure
        if (credential.credentialSubject) {
            const subjects = Array.isArray(credential.credentialSubject)
                ? credential.credentialSubject
                : [credential.credentialSubject];
            for (let i = 0; i < subjects.length; i++) {
                const subject = subjects[i];
                if (typeof subject !== 'object' || subject === null) {
                    errors.push(`credentialSubject[${i}] must be an object`);
                }
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate presentation structure
     */
    validatePresentationStructure(presentation) {
        const errors = [];
        const warnings = [];
        // Required fields per W3C spec
        const requiredFields = ['@context', 'type'];
        for (const field of requiredFields) {
            if (!presentation[field]) {
                errors.push(`Missing required field: ${field}`);
            }
        }
        // Validate type structure
        if (presentation.type) {
            const types = Array.isArray(presentation.type) ? presentation.type : [presentation.type];
            if (!types.includes('VerifiablePresentation')) {
                errors.push('Type must include VerifiablePresentation');
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate credential type
     */
    validateCredentialType(credential, allowedTypes) {
        const errors = [];
        const warnings = [];
        if (!allowedTypes || allowedTypes.length === 0) {
            return { valid: true, errors, warnings };
        }
        const types = Array.isArray(credential.type) ? credential.type : [credential.type];
        const hasAllowedType = types.some(type => allowedTypes.includes(type));
        if (!hasAllowedType) {
            errors.push(`Credential type must be one of: ${allowedTypes.join(', ')}`);
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate issuer
     */
    validateIssuer(credential, trustedIssuers) {
        const errors = [];
        const warnings = [];
        if (!trustedIssuers || trustedIssuers.length === 0) {
            return { valid: true, errors, warnings };
        }
        const issuerUri = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
        if (!trustedIssuers.includes(issuerUri)) {
            errors.push(`Issuer ${issuerUri} is not in trusted issuers list`);
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate temporal constraints
     */
    validateTemporalConstraints(credential) {
        const errors = [];
        const warnings = [];
        const now = new Date();
        // Validate validFrom
        if (credential.validFrom) {
            try {
                const validFrom = new Date(credential.validFrom);
                if (isNaN(validFrom.getTime())) {
                    errors.push('Invalid validFrom date format');
                }
                else if (now < validFrom) {
                    errors.push('Credential is not yet valid');
                }
            }
            catch {
                errors.push('Invalid validFrom date format');
            }
        }
        // Validate validUntil
        if (credential.validUntil) {
            try {
                const validUntil = new Date(credential.validUntil);
                if (isNaN(validUntil.getTime())) {
                    errors.push('Invalid validUntil date format');
                }
                else if (now > validUntil) {
                    errors.push('Credential has expired');
                }
            }
            catch {
                errors.push('Invalid validUntil date format');
            }
        }
        // Validate validFrom is before validUntil
        if (credential.validFrom && credential.validUntil) {
            const validFrom = new Date(credential.validFrom);
            const validUntil = new Date(credential.validUntil);
            if (validFrom >= validUntil) {
                errors.push('validFrom must be before validUntil');
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate credential proof
     */
    async validateCredentialProof(credential) {
        const errors = [];
        const warnings = [];
        if (!credential.proof) {
            return { valid: true, errors, warnings };
        }
        const proofs = Array.isArray(credential.proof) ? credential.proof : [credential.proof];
        for (const proof of proofs) {
            // Basic proof structure validation
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
            // Validate proof purpose
            if (proof.proofPurpose && proof.proofPurpose !== 'assertionMethod') {
                warnings.push(`Unexpected proof purpose: ${proof.proofPurpose}`);
            }
            // Validate created timestamp
            if (proof.created) {
                try {
                    const created = new Date(proof.created);
                    if (isNaN(created.getTime())) {
                        errors.push('Invalid proof created date format');
                    }
                }
                catch {
                    errors.push('Invalid proof created date format');
                }
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate presentation proof
     */
    async validatePresentationProof(presentation) {
        const errors = [];
        const warnings = [];
        if (!presentation.proof) {
            return { valid: true, errors, warnings };
        }
        const proofs = Array.isArray(presentation.proof) ? presentation.proof : [presentation.proof];
        for (const proof of proofs) {
            // Basic proof structure validation
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
            // Validate proof purpose for presentations
            if (proof.proofPurpose && proof.proofPurpose !== 'authentication') {
                warnings.push(`Unexpected proof purpose for presentation: ${proof.proofPurpose}`);
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate credential schema
     */
    async validateCredentialSchema(credential) {
        const errors = [];
        const warnings = [];
        // Placeholder for schema validation
        // In a real implementation, this would fetch and validate against the schema
        warnings.push('Schema validation not fully implemented');
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate revocation status
     */
    async validateRevocationStatus(credential) {
        const errors = [];
        const warnings = [];
        // Placeholder for revocation status checking
        // In a real implementation, this would check the credential status
        warnings.push('Revocation status checking not fully implemented');
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate required fields
     */
    validateRequiredFields(credential, requiredFields) {
        const errors = [];
        const warnings = [];
        for (const field of requiredFields) {
            if (!this.hasNestedProperty(credential, field)) {
                errors.push(`Missing required field: ${field}`);
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Check if object has nested property
     */
    hasNestedProperty(obj, path) {
        return path.split('.').reduce((current, prop) => {
            return current && current[prop] !== undefined;
        }, obj) !== undefined;
    }
}
exports.ValidationEngine = ValidationEngine;
//# sourceMappingURL=index.js.map