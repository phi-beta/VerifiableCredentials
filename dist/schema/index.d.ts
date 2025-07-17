/**
 * Schema validation system for Verifiable Credentials
 * Supports JSON Schema validation with built-in schemas
 */
import { AnySchema } from 'ajv';
import { VerifiableCredential, VerifiablePresentation, ValidationResult } from '../types';
declare const BUILT_IN_SCHEMAS: Record<string, AnySchema>;
export declare class SchemaValidator {
    private ajv;
    private customSchemas;
    constructor();
    /**
     * Register built-in schemas
     */
    private registerBuiltInSchemas;
    /**
     * Add a custom schema
     */
    addSchema(schemaId: string, schema: AnySchema): void;
    /**
     * Remove a schema
     */
    removeSchema(schemaId: string): void;
    /**
     * Validate a credential against its schema
     */
    validateCredential(credential: VerifiableCredential, schemaId?: string): ValidationResult;
    /**
     * Validate a presentation against its schema
     */
    validatePresentation(presentation: VerifiablePresentation, schemaId?: string): ValidationResult;
    /**
     * Resolve schema ID from credential type
     */
    private resolveSchemaId;
    /**
     * Check if a schema exists
     */
    hasSchema(schemaId: string): boolean;
    /**
     * Format AJV error for display
     */
    private formatError;
    /**
     * Validate credential schema reference
     */
    private validateCredentialSchema;
    /**
     * Get all available schema IDs
     */
    getAvailableSchemas(): string[];
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
export { BUILT_IN_SCHEMAS };
//# sourceMappingURL=index.d.ts.map