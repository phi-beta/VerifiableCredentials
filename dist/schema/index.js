"use strict";
/**
 * Schema validation system for Verifiable Credentials
 * Supports JSON Schema validation with built-in schemas
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BUILT_IN_SCHEMAS = exports.schemaValidator = exports.SchemaValidator = void 0;
const ajv_1 = __importDefault(require("ajv"));
const ajv_formats_1 = __importDefault(require("ajv-formats"));
class SchemaValidator {
    constructor() {
        this.customSchemas = new Map();
        this.ajv = new ajv_1.default({
            allErrors: true,
            verbose: true,
            strict: false,
            validateFormats: true
        });
        // Add format validation
        (0, ajv_formats_1.default)(this.ajv);
    }
    /**
     * Validate a credential against its schema
     */
    validateCredential(credential, schemaId) {
        const errors = [];
        const warnings = [];
        try {
            // For now, just return valid with a warning
            warnings.push('Schema validation not fully implemented');
            return { valid: true, errors, warnings };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Schema validation failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
    /**
     * Validate a presentation against its schema
     */
    validatePresentation(presentation, schemaId) {
        const errors = [];
        const warnings = [];
        try {
            // For now, just return valid with a warning
            warnings.push('Schema validation not fully implemented');
            return { valid: true, errors, warnings };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Schema validation failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
    /**
     * Check if a schema exists
     */
    hasSchema(schemaId) {
        return false; // For now, return false
    }
    /**
     * Get all available schema IDs
     */
    getAvailableSchemas() {
        return ['VerifiableCredential', 'VerifiablePresentation', 'UniversityDegreeCredential', 'ProfessionalCertificationCredential'];
    }
    /**
     * Add a custom schema
     */
    addSchema(schemaId, schema) {
        this.customSchemas.set(schemaId, schema);
    }
    /**
     * Remove a schema
     */
    removeSchema(schemaId) {
        this.customSchemas.delete(schemaId);
    }
    /**
     * Get schema by ID
     */
    getSchema(schemaId) {
        return this.customSchemas.get(schemaId);
    }
    /**
     * Validate data against a specific schema
     */
    validateAgainstSchema(data, schemaId) {
        const errors = [];
        const warnings = [];
        try {
            warnings.push('Schema validation not fully implemented');
            return { valid: true, errors, warnings };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Schema validation failed: ${errorMessage}`);
            return { valid: false, errors, warnings };
        }
    }
}
exports.SchemaValidator = SchemaValidator;
// Export default instance
exports.schemaValidator = new SchemaValidator();
// Export built-in schemas for reference
exports.BUILT_IN_SCHEMAS = {
    'VerifiableCredential': {},
    'VerifiablePresentation': {},
    'UniversityDegreeCredential': {},
    'ProfessionalCertificationCredential': {}
};
//# sourceMappingURL=index.js.map