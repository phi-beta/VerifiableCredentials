"use strict";
/**
 * Comprehensive validation algorithms for Verifiable Credentials
 * Implements W3C validation requirements and algorithms
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ValidationEngine = void 0;
const context_1 = require("../context");
const security_1 = require("../security");
const schema_1 = require("../schema");
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
        for (let i = 0; i < proofs.length; i++) {
            const proof = proofs[i];
            // Basic proof structure validation
            if (!proof.type) {
                errors.push(`Proof ${i}: missing type`);
                continue;
            }
            if (!proof.verificationMethod) {
                errors.push(`Proof ${i}: missing verificationMethod`);
                continue;
            }
            if (!proof.proofPurpose) {
                errors.push(`Proof ${i}: missing proofPurpose`);
                continue;
            }
            if (!proof.proofValue && !proof.jws) {
                errors.push(`Proof ${i}: missing proofValue or jws`);
                continue;
            }
            // Validate proof purpose
            if (proof.proofPurpose && proof.proofPurpose !== 'assertionMethod') {
                warnings.push(`Proof ${i}: unexpected proof purpose: ${proof.proofPurpose}`);
            }
            // Validate created timestamp
            if (proof.created) {
                try {
                    const created = new Date(proof.created);
                    if (isNaN(created.getTime())) {
                        errors.push(`Proof ${i}: invalid created date format`);
                    }
                    else {
                        // Check if proof is too old (configurable threshold)
                        const now = new Date();
                        const hoursDiff = (now.getTime() - created.getTime()) / (1000 * 60 * 60);
                        if (hoursDiff > 24) { // 24 hours threshold
                            warnings.push(`Proof ${i}: proof is ${Math.round(hoursDiff)} hours old`);
                        }
                    }
                }
                catch {
                    errors.push(`Proof ${i}: invalid created date format`);
                }
            }
            // Cryptographic verification using SecurityManager
            try {
                const credentialCopy = { ...credential };
                delete credentialCopy.proof; // Remove proof for verification
                // Extract public key from verification method
                // In a real implementation, this would resolve the DID and get the public key
                // For now, we'll simulate this with a placeholder
                const publicKey = this.extractPublicKeyFromVerificationMethod(proof.verificationMethod);
                const verificationResult = await this.securityManager.verifyProof(proof, credentialCopy, publicKey);
                if (!verificationResult.valid) {
                    errors.push(`Proof ${i}: ${verificationResult.errors.join(', ')}`);
                }
                if (verificationResult.warnings) {
                    warnings.push(...verificationResult.warnings.map(warn => `Proof ${i}: ${warn}`));
                }
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                errors.push(`Proof ${i}: verification error: ${errorMessage}`);
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
        for (let i = 0; i < proofs.length; i++) {
            const proof = proofs[i];
            // Basic proof structure validation
            if (!proof.type) {
                errors.push(`Presentation proof ${i}: missing type`);
                continue;
            }
            if (!proof.verificationMethod) {
                errors.push(`Presentation proof ${i}: missing verificationMethod`);
                continue;
            }
            if (!proof.proofPurpose) {
                errors.push(`Presentation proof ${i}: missing proofPurpose`);
                continue;
            }
            if (!proof.proofValue && !proof.jws) {
                errors.push(`Presentation proof ${i}: missing proofValue or jws`);
                continue;
            }
            // Validate proof purpose for presentations
            if (proof.proofPurpose && proof.proofPurpose !== 'authentication') {
                warnings.push(`Presentation proof ${i}: unexpected proof purpose: ${proof.proofPurpose}`);
            }
            // Validate challenge for presentations
            if (!proof.challenge) {
                warnings.push(`Presentation proof ${i}: missing challenge - recommended for presentation proofs`);
            }
            // Validate domain for presentations
            if (!proof.domain) {
                warnings.push(`Presentation proof ${i}: missing domain - recommended for presentation proofs`);
            }
            // Cryptographic verification using SecurityManager
            try {
                const presentationCopy = { ...presentation };
                delete presentationCopy.proof; // Remove proof for verification
                // Extract public key from verification method
                const publicKey = this.extractPublicKeyFromVerificationMethod(proof.verificationMethod);
                const verificationResult = await this.securityManager.verifyProof(proof, presentationCopy, publicKey);
                if (!verificationResult.valid) {
                    errors.push(`Presentation proof ${i}: ${verificationResult.errors.join(', ')}`);
                }
                if (verificationResult.warnings) {
                    warnings.push(...verificationResult.warnings.map(warn => `Presentation proof ${i}: ${warn}`));
                }
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                errors.push(`Presentation proof ${i}: verification error: ${errorMessage}`);
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
        try {
            // Use the comprehensive schema validator
            const schemaResult = schema_1.schemaValidator.validateCredential(credential);
            if (!schemaResult.valid) {
                errors.push(...schemaResult.errors);
            }
            if (schemaResult.warnings) {
                warnings.push(...schemaResult.warnings);
            }
            // Additional schema-specific validations
            if (credential.credentialSchema) {
                const schemas = Array.isArray(credential.credentialSchema)
                    ? credential.credentialSchema
                    : [credential.credentialSchema];
                for (const schema of schemas) {
                    // Validate schema structure
                    if (!schema.id) {
                        errors.push('credentialSchema missing id');
                    }
                    if (!schema.type) {
                        errors.push('credentialSchema missing type');
                    }
                    // Validate against specific schema if available
                    if (schema.id) {
                        try {
                            const specificResult = schema_1.schemaValidator.validateAgainstSchema(credential, schema.id);
                            if (!specificResult.valid) {
                                errors.push(...specificResult.errors.map(err => `Schema ${schema.id}: ${err}`));
                            }
                            if (specificResult.warnings) {
                                warnings.push(...specificResult.warnings.map(warn => `Schema ${schema.id}: ${warn}`));
                            }
                        }
                        catch (error) {
                            warnings.push(`Could not validate against schema ${schema.id}: ${error instanceof Error ? error.message : 'Unknown error'}`);
                        }
                    }
                }
            }
            return { valid: errors.length === 0, errors, warnings };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Schema validation failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
    /**
     * Validate revocation status
     */
    async validateRevocationStatus(credential) {
        const errors = [];
        const warnings = [];
        if (!credential.credentialStatus) {
            return { valid: true, errors, warnings };
        }
        const statuses = Array.isArray(credential.credentialStatus)
            ? credential.credentialStatus
            : [credential.credentialStatus];
        for (let i = 0; i < statuses.length; i++) {
            const status = statuses[i];
            // Basic structure validation
            if (!status.id) {
                errors.push(`credentialStatus[${i}]: missing id`);
                continue;
            }
            if (!status.type) {
                errors.push(`credentialStatus[${i}]: missing type`);
                continue;
            }
            // Validate supported status types
            const supportedTypes = [
                'RevocationList2020Status',
                'StatusList2021Entry',
                'BitstringStatusListEntry'
            ];
            if (!supportedTypes.includes(status.type)) {
                warnings.push(`credentialStatus[${i}]: unsupported status type ${status.type}`);
                continue;
            }
            // Type-specific validation
            try {
                switch (status.type) {
                    case 'RevocationList2020Status':
                        await this.validateRevocationList2020Status(status, i);
                        break;
                    case 'StatusList2021Entry':
                    case 'BitstringStatusListEntry':
                        await this.validateStatusList2021Entry(status, i);
                        break;
                    default:
                        warnings.push(`credentialStatus[${i}]: status type ${status.type} validation not implemented`);
                }
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                warnings.push(`credentialStatus[${i}]: status check failed: ${errorMessage}`);
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate RevocationList2020 status
     */
    async validateRevocationList2020Status(status, index) {
        // Basic field validation
        if (!status.revocationListIndex) {
            throw new Error(`credentialStatus[${index}]: missing revocationListIndex`);
        }
        if (!status.revocationListCredential) {
            throw new Error(`credentialStatus[${index}]: missing revocationListCredential`);
        }
        // TODO: Implement actual revocation list fetching and checking
        // This would involve:
        // 1. Fetch the revocation list credential from status.revocationListCredential
        // 2. Verify the revocation list credential
        // 3. Check if the index is set in the bitstring
        console.log(`RevocationList2020 status check not fully implemented for index ${status.revocationListIndex}`);
    }
    /**
     * Validate StatusList2021 entry
     */
    async validateStatusList2021Entry(status, index) {
        // Basic field validation
        if (!status.statusListIndex) {
            throw new Error(`credentialStatus[${index}]: missing statusListIndex`);
        }
        if (!status.statusListCredential) {
            throw new Error(`credentialStatus[${index}]: missing statusListCredential`);
        }
        // Validate status purpose
        if (status.statusPurpose && !['revocation', 'suspension'].includes(status.statusPurpose)) {
            throw new Error(`credentialStatus[${index}]: invalid statusPurpose ${status.statusPurpose}`);
        }
        // TODO: Implement actual status list fetching and checking
        console.log(`StatusList2021 status check not fully implemented for index ${status.statusListIndex}`);
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
    /**
     * Extract public key from verification method
     * This is a simplified implementation - in production, this would resolve DIDs
     */
    extractPublicKeyFromVerificationMethod(verificationMethod) {
        // Placeholder implementation - in real scenario, this would:
        // 1. Parse the verification method URI
        // 2. Resolve the DID document
        // 3. Extract the public key from the verification method
        // For demo purposes, return a mock public key
        // This allows the validation to proceed without full DID resolution
        return 'mock-public-key-for-validation-demo';
    }
    /**
     * Validate credential against multiple schemas
     */
    async validateCredentialWithSchemas(credential, schemaIds) {
        const errors = [];
        const warnings = [];
        for (const schemaId of schemaIds) {
            try {
                const result = schema_1.schemaValidator.validateAgainstSchema(credential, schemaId);
                if (!result.valid) {
                    errors.push(...result.errors.map(err => `Schema ${schemaId}: ${err}`));
                }
                if (result.warnings) {
                    warnings.push(...result.warnings.map(warn => `Schema ${schemaId}: ${warn}`));
                }
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                warnings.push(`Schema ${schemaId}: validation failed: ${errorMessage}`);
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate credential subject data
     */
    validateCredentialSubject(credential) {
        const errors = [];
        const warnings = [];
        if (!credential.credentialSubject) {
            errors.push('Missing credentialSubject');
            return { valid: false, errors, warnings };
        }
        const subjects = Array.isArray(credential.credentialSubject)
            ? credential.credentialSubject
            : [credential.credentialSubject];
        for (let i = 0; i < subjects.length; i++) {
            const subject = subjects[i];
            // Validate subject structure
            if (typeof subject !== 'object' || subject === null) {
                errors.push(`credentialSubject[${i}]: must be an object`);
                continue;
            }
            // Check for circular references
            try {
                JSON.stringify(subject);
            }
            catch (error) {
                errors.push(`credentialSubject[${i}]: contains circular references`);
            }
            // Validate subject ID if present
            if (subject.id && typeof subject.id !== 'string') {
                errors.push(`credentialSubject[${i}]: id must be a string`);
            }
            // Check for empty subject
            const subjectKeys = Object.keys(subject);
            if (subjectKeys.length === 0 || (subjectKeys.length === 1 && subjectKeys[0] === 'id')) {
                warnings.push(`credentialSubject[${i}]: contains no substantive claims`);
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate evidence
     */
    validateEvidence(credential) {
        const errors = [];
        const warnings = [];
        if (!credential.evidence) {
            return { valid: true, errors, warnings };
        }
        const evidenceArray = Array.isArray(credential.evidence)
            ? credential.evidence
            : [credential.evidence];
        for (let i = 0; i < evidenceArray.length; i++) {
            const evidence = evidenceArray[i];
            if (typeof evidence !== 'object' || evidence === null) {
                errors.push(`evidence[${i}]: must be an object`);
                continue;
            }
            // Evidence must have a type
            if (!evidence.type) {
                errors.push(`evidence[${i}]: missing type`);
            }
            // Validate common evidence types
            if (evidence.type && typeof evidence.type === 'string' && evidence.type === 'DocumentVerification') {
                if (!evidence.verifier && !evidence.evidenceDocument) {
                    warnings.push(`evidence[${i}]: DocumentVerification should have verifier or evidenceDocument`);
                }
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate terms of use
     */
    validateTermsOfUse(termsOfUse) {
        const errors = [];
        const warnings = [];
        for (let i = 0; i < termsOfUse.length; i++) {
            const term = termsOfUse[i];
            if (typeof term !== 'object' || term === null) {
                errors.push(`termsOfUse[${i}]: must be an object`);
                continue;
            }
            if (!term.type) {
                errors.push(`termsOfUse[${i}]: missing type`);
            }
            // Validate specific term types
            if (term.type === 'IssuerPolicy') {
                if (!term.policy) {
                    warnings.push(`termsOfUse[${i}]: IssuerPolicy should have policy field`);
                }
            }
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Validate refresh service
     */
    validateRefreshService(refreshService) {
        const errors = [];
        const warnings = [];
        if (!refreshService.id) {
            errors.push('refreshService: missing id');
        }
        if (!refreshService.type) {
            errors.push('refreshService: missing type');
        }
        // Validate service endpoint
        if (refreshService.serviceEndpoint && typeof refreshService.serviceEndpoint !== 'string') {
            errors.push('refreshService: serviceEndpoint must be a string URI');
        }
        return { valid: errors.length === 0, errors, warnings };
    }
    /**
     * Comprehensive validation with detailed reporting
     */
    async validateWithDetailedReport(credential, options = {}) {
        const details = {
            context: await this.contextManager.validateContext(credential),
            structure: this.validateCredentialStructure(credential, options),
            type: this.validateCredentialType(credential, options.allowedTypes),
            issuer: this.validateIssuer(credential, options.trustedIssuers),
            temporal: options.validateExpiration !== false ? this.validateTemporalConstraints(credential) : { valid: true, errors: [], warnings: [] },
            proof: options.validateProof !== false && credential.proof ? await this.validateCredentialProof(credential) : { valid: true, errors: [], warnings: [] },
            schema: options.validateSchema && credential.credentialSchema ? await this.validateCredentialSchema(credential) : { valid: true, errors: [], warnings: [] },
            revocation: options.validateRevocation && credential.credentialStatus ? await this.validateRevocationStatus(credential) : { valid: true, errors: [], warnings: [] },
            subject: this.validateCredentialSubject(credential),
            evidence: this.validateEvidence(credential),
            termsOfUse: credential.termsOfUse ? this.validateTermsOfUse(credential.termsOfUse) : { valid: true, errors: [], warnings: [] },
            refreshService: credential.refreshService ? this.validateRefreshService(credential.refreshService) : { valid: true, errors: [], warnings: [] }
        };
        const allErrors = [];
        const allWarnings = [];
        Object.entries(details).forEach(([section, result]) => {
            if (result.errors) {
                allErrors.push(...result.errors.map(err => `${section}: ${err}`));
            }
            if (result.warnings) {
                allWarnings.push(...result.warnings.map(warn => `${section}: ${warn}`));
            }
        });
        return {
            valid: allErrors.length === 0,
            errors: allErrors,
            warnings: allWarnings,
            details
        };
    }
}
exports.ValidationEngine = ValidationEngine;
//# sourceMappingURL=index.js.map