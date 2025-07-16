/**
 * Schema validation system for Verifiable Credentials
 * Supports JSON Schema validation with built-in schemas
 */
import { AnySchema } from 'ajv';
import { VerifiableCredential, VerifiablePresentation, ValidationResult } from '../types';
export declare class SchemaValidator {
    private ajv;
    private customSchemas;
    constructor();
    /**
     * Validate a credential against its schema
     */
    validateCredential(credential: VerifiableCredential, schemaId?: string): ValidationResult;
    /**
     * Validate a presentation against its schema
     */
    validatePresentation(presentation: VerifiablePresentation, schemaId?: string): ValidationResult;
    /**
     * Check if a schema exists
     */
    hasSchema(schemaId: string): boolean;
    /**
     * Get all available schema IDs
     */
    getAvailableSchemas(): string[];
    /**
     * Add a custom schema
     */
    addSchema(schemaId: string, schema: AnySchema): void;
    /**
     * Remove a schema
     */
    removeSchema(schemaId: string): void;
    /**
     * Get schema by ID
     */
    getSchema(schemaId: string): AnySchema | undefined;
    /**
     * Validate data against a specific schema
     */
    validateAgainstSchema(data: any, schemaId: string): ValidationResult;
}
export declare const schemaValidator: SchemaValidator;
export declare const BUILT_IN_SCHEMAS: {
    VerifiableCredential: {};
    VerifiablePresentation: {};
    UniversityDegreeCredential: {};
    ProfessionalCertificationCredential: {};
};
//# sourceMappingURL=index.d.ts.map