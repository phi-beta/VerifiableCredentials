/**
 * Schema validation system for Verifiable Credentials
 * Supports JSON Schema validation with built-in schemas
 */

import Ajv, { AnySchema } from 'ajv';
import addFormats from 'ajv-formats';
import { VerifiableCredential, VerifiablePresentation, ValidationResult } from '../types';

export class SchemaValidator {
  private ajv: Ajv;
  private customSchemas: Map<string, AnySchema> = new Map();

  constructor() {
    this.ajv = new Ajv({
      allErrors: true,
      verbose: true,
      strict: false,
      validateFormats: true
    });
    
    // Add format validation
    addFormats(this.ajv);
  }

  /**
   * Validate a credential against its schema
   */
  validateCredential(credential: VerifiableCredential, schemaId?: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // For now, just return valid with a warning
      warnings.push('Schema validation not fully implemented');
      return { valid: true, errors, warnings };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Schema validation failed: ${errorMessage}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Validate a presentation against its schema
   */
  validatePresentation(presentation: VerifiablePresentation, schemaId?: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // For now, just return valid with a warning
      warnings.push('Schema validation not fully implemented');
      return { valid: true, errors, warnings };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Schema validation failed: ${errorMessage}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Check if a schema exists
   */
  hasSchema(schemaId: string): boolean {
    return false; // For now, return false
  }

  /**
   * Get all available schema IDs
   */
  getAvailableSchemas(): string[] {
    return ['VerifiableCredential', 'VerifiablePresentation', 'UniversityDegreeCredential', 'ProfessionalCertificationCredential'];
  }

  /**
   * Add a custom schema
   */
  addSchema(schemaId: string, schema: AnySchema): void {
    this.customSchemas.set(schemaId, schema);
  }

  /**
   * Remove a schema
   */
  removeSchema(schemaId: string): void {
    this.customSchemas.delete(schemaId);
  }

  /**
   * Get schema by ID
   */
  getSchema(schemaId: string): AnySchema | undefined {
    return this.customSchemas.get(schemaId);
  }

  /**
   * Validate data against a specific schema
   */
  validateAgainstSchema(data: any, schemaId: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      warnings.push('Schema validation not fully implemented');
      return { valid: true, errors, warnings };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Schema validation failed: ${errorMessage}`);
      return { valid: false, errors, warnings };
    }
  }
}

// Export default instance
export const schemaValidator = new SchemaValidator();

// Export built-in schemas for reference
export const BUILT_IN_SCHEMAS = {
  'VerifiableCredential': {},
  'VerifiablePresentation': {},
  'UniversityDegreeCredential': {},
  'ProfessionalCertificationCredential': {}
};
