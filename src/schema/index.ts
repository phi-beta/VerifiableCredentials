/**
 * Schema validation system for Verifiable Credentials
 * Supports JSON Schema validation with built-in schemas
 */

import Ajv, { AnySchema } from 'ajv';
import addFormats from 'ajv-formats';
import { VerifiableCredential, VerifiablePresentation, ValidationResult } from '../types';

// Define the VerifiableCredential schema first
const VerifiableCredentialSchema: AnySchema = {
  $id: 'VerifiableCredential',
  $schema: 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  required: ['@context', 'type', 'issuer', 'credentialSubject'],
  properties: {
    '@context': {
      oneOf: [
        { type: 'string' },
        {
          type: 'array',
          items: { type: 'string' },
          minItems: 1
        }
      ]
    },
    id: { type: 'string', format: 'uri' },
    type: {
      oneOf: [
        { type: 'string' },
        {
          type: 'array',
          items: { type: 'string' },
          minItems: 1,
          contains: { const: 'VerifiableCredential' }
        }
      ]
    },
    issuer: {
      oneOf: [
        { type: 'string', format: 'uri' },
        {
          type: 'object',
          required: ['id'],
          properties: {
            id: { type: 'string', format: 'uri' },
            name: { type: 'string' },
            description: { type: 'string' },
            url: { type: 'string', format: 'uri' },
            image: { type: 'string', format: 'uri' }
          }
        }
      ]
    },
    validFrom: { type: 'string', format: 'date-time' },
    validUntil: { type: 'string', format: 'date-time' },
    credentialSubject: {
      oneOf: [
        {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uri' }
          }
        },
        {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uri' }
            }
          }
        }
      ]
    },
    proof: {
      oneOf: [
        {
          type: 'object',
          required: ['type'],
          properties: {
            type: { type: 'string' },
            created: { type: 'string', format: 'date-time' },
            verificationMethod: { type: 'string', format: 'uri' },
            proofPurpose: { type: 'string' },
            challenge: { type: 'string' },
            domain: { type: 'string' },
            proofValue: { type: 'string' },
            jws: { type: 'string' }
          }
        },
        {
          type: 'array',
          items: {
            type: 'object',
            required: ['type'],
            properties: {
              type: { type: 'string' },
              created: { type: 'string', format: 'date-time' },
              verificationMethod: { type: 'string', format: 'uri' },
              proofPurpose: { type: 'string' },
              challenge: { type: 'string' },
              domain: { type: 'string' },
              proofValue: { type: 'string' },
              jws: { type: 'string' }
            }
          }
        }
      ]
    },
    credentialStatus: {
      type: 'object',
      required: ['id', 'type'],
      properties: {
        id: { type: 'string', format: 'uri' },
        type: { type: 'string' },
        statusPurpose: { type: 'string' },
        statusListIndex: { type: 'string' },
        statusListCredential: { type: 'string', format: 'uri' }
      }
    },
    credentialSchema: {
      type: 'object',
      required: ['id', 'type'],
      properties: {
        id: { type: 'string', format: 'uri' },
        type: { type: 'string' }
      }
    },
    refreshService: {
      type: 'object',
      required: ['id', 'type'],
      properties: {
        id: { type: 'string', format: 'uri' },
        type: { type: 'string' }
      }
    },
    termsOfUse: {
      type: 'array',
      items: {
        type: 'object',
        required: ['type'],
        properties: {
          type: { type: 'string' },
          id: { type: 'string', format: 'uri' },
          profile: { type: 'string', format: 'uri' }
        }
      }
    },
    evidence: {
      type: 'array',
      items: {
        type: 'object',
        required: ['type'],
        properties: {
          id: { type: 'string', format: 'uri' },
          type: {
            type: 'array',
            items: { type: 'string' }
          }
        }
      }
    }
  }
};

// Built-in schemas for common credential types
const BUILT_IN_SCHEMAS: Record<string, AnySchema> = {
  'VerifiableCredential': VerifiableCredentialSchema,
  
  'VerifiablePresentation': {
    $id: 'VerifiablePresentation',
    $schema: 'http://json-schema.org/draft-07/schema#',
    type: 'object',
    required: ['@context', 'type'],
    properties: {
      '@context': {
        oneOf: [
          { type: 'string' },
          {
            type: 'array',
            items: { type: 'string' },
            minItems: 1
          }
        ]
      },
      id: { type: 'string', format: 'uri' },
      type: {
        oneOf: [
          { type: 'string' },
          {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
            contains: { const: 'VerifiablePresentation' }
          }
        ]
      },
      verifiableCredential: {
        type: 'array',
        items: { $ref: 'VerifiableCredential' }
      },
      holder: { type: 'string', format: 'uri' },
      proof: {
        oneOf: [
          {
            type: 'object',
            required: ['type'],
            properties: {
              type: { type: 'string' },
              created: { type: 'string', format: 'date-time' },
              verificationMethod: { type: 'string', format: 'uri' },
              proofPurpose: { type: 'string' },
              challenge: { type: 'string' },
              domain: { type: 'string' },
              proofValue: { type: 'string' },
              jws: { type: 'string' }
            }
          },
          {
            type: 'array',
            items: {
              type: 'object',
              required: ['type'],
              properties: {
                type: { type: 'string' },
                created: { type: 'string', format: 'date-time' },
                verificationMethod: { type: 'string', format: 'uri' },
                proofPurpose: { type: 'string' },
                challenge: { type: 'string' },
                domain: { type: 'string' },
                proofValue: { type: 'string' },
                jws: { type: 'string' }
              }
            }
          }
        ]
      },
      termsOfUse: {
        type: 'array',
        items: {
          type: 'object',
          required: ['type'],
          properties: {
            type: { type: 'string' },
            id: { type: 'string', format: 'uri' },
            profile: { type: 'string', format: 'uri' }
          }
        }
      }
    }
  },

  'UniversityDegreeCredential': {
    $id: 'UniversityDegreeCredential',
    $schema: 'http://json-schema.org/draft-07/schema#',
    allOf: [
      { $ref: 'VerifiableCredential' },
      {
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            required: ['id', 'name', 'degree'],
            properties: {
              id: { type: 'string', format: 'uri' },
              name: { type: 'string' },
              degree: {
                type: 'object',
                required: ['type', 'name'],
                properties: {
                  type: { type: 'string' },
                  name: { type: 'string' },
                  degreeSchool: { type: 'string' }
                }
              },
              graduationDate: { type: 'string', format: 'date' }
            }
          }
        }
      }
    ]
  },

  'ProfessionalCertificationCredential': {
    $id: 'ProfessionalCertificationCredential',
    $schema: 'http://json-schema.org/draft-07/schema#',
    allOf: [
      { $ref: 'VerifiableCredential' },
      {
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            required: ['id', 'name', 'certification'],
            properties: {
              id: { type: 'string', format: 'uri' },
              name: { type: 'string' },
              certification: {
                type: 'object',
                required: ['type', 'name'],
                properties: {
                  type: { type: 'string' },
                  name: { type: 'string' },
                  certificationAuthority: { type: 'string' }
                }
              },
              examDate: { type: 'string', format: 'date' },
              score: { type: 'number', minimum: 0, maximum: 100 }
            }
          }
        }
      }
    ]
  }
};

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

    // Register built-in schemas
    this.registerBuiltInSchemas();
  }

  /**
   * Register built-in schemas
   */
  private registerBuiltInSchemas(): void {
    for (const [schemaId, schema] of Object.entries(BUILT_IN_SCHEMAS)) {
      this.ajv.addSchema(schema, schemaId);
    }
  }

  /**
   * Add a custom schema
   */
  addSchema(schemaId: string, schema: AnySchema): void {
    this.customSchemas.set(schemaId, schema);
    this.ajv.addSchema(schema, schemaId);
  }

  /**
   * Remove a schema
   */
  removeSchema(schemaId: string): void {
    this.customSchemas.delete(schemaId);
    this.ajv.removeSchema(schemaId);
  }

  /**
   * Validate a credential against its schema
   */
  validateCredential(credential: VerifiableCredential, schemaId?: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Determine schema ID
      const resolvedSchemaId = schemaId || this.resolveSchemaId(credential);
      
      if (!resolvedSchemaId) {
        warnings.push('No schema found for validation');
        return { valid: true, errors, warnings };
      }

      // Validate against schema
      const validate = this.ajv.getSchema(resolvedSchemaId);
      if (!validate) {
        errors.push(`Schema not found: ${resolvedSchemaId}`);
        return { valid: false, errors, warnings };
      }

      const valid = validate(credential);
      if (!valid && validate.errors) {
        for (const error of validate.errors) {
          const errorMessage = this.formatError(error);
          errors.push(errorMessage);
        }
      }

      // Additional validation for credential schema reference
      if (credential.credentialSchema) {
        const schemaResult = this.validateCredentialSchema(credential);
        if (!schemaResult.valid) {
          errors.push(...schemaResult.errors);
          warnings.push(...(schemaResult.warnings || []));
        }
      }

      return { valid: errors.length === 0, errors, warnings };
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
      // Use VerifiablePresentation schema by default
      const resolvedSchemaId = schemaId || 'VerifiablePresentation';
      
      const validate = this.ajv.getSchema(resolvedSchemaId);
      if (!validate) {
        errors.push(`Schema not found: ${resolvedSchemaId}`);
        return { valid: false, errors, warnings };
      }

      const valid = validate(presentation);
      if (!valid && validate.errors) {
        for (const error of validate.errors) {
          const errorMessage = this.formatError(error);
          errors.push(errorMessage);
        }
      }

      // Validate embedded credentials
      if (presentation.verifiableCredential) {
        for (let i = 0; i < presentation.verifiableCredential.length; i++) {
          const credential = presentation.verifiableCredential[i];
          const credentialResult = this.validateCredential(credential);
          
          if (!credentialResult.valid) {
            errors.push(...credentialResult.errors.map(err => `Credential ${i}: ${err}`));
          }
          if (credentialResult.warnings) {
            warnings.push(...credentialResult.warnings.map(warn => `Credential ${i}: ${warn}`));
          }
        }
      }

      return { valid: errors.length === 0, errors, warnings };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Presentation schema validation failed: ${errorMessage}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Resolve schema ID from credential type
   */
  private resolveSchemaId(credential: VerifiableCredential): string | null {
    const types = Array.isArray(credential.type) ? credential.type : [credential.type];
    
    // Look for specific credential types first
    for (const type of types) {
      if (type !== 'VerifiableCredential' && this.hasSchema(type)) {
        return type;
      }
    }
    
    // Fall back to base VerifiableCredential schema
    return 'VerifiableCredential';
  }

  /**
   * Check if a schema exists
   */
  hasSchema(schemaId: string): boolean {
    return this.ajv.getSchema(schemaId) !== undefined;
  }

  /**
   * Format AJV error for display
   */
  private formatError(error: any): string {
    const instancePath = error.instancePath || '';
    const message = error.message || 'Validation failed';
    
    if (instancePath) {
      return `${instancePath}: ${message}`;
    }
    
    return message;
  }

  /**
   * Validate credential schema reference
   */
  private validateCredentialSchema(credential: VerifiableCredential): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!credential.credentialSchema) {
      return { valid: true, errors, warnings };
    }

    const schema = credential.credentialSchema;
    
    // Validate schema structure
    if (!schema.id) {
      errors.push('credentialSchema missing id');
    }
    if (!schema.type) {
      errors.push('credentialSchema missing type');
    }

    // Try to validate against the referenced schema if available
    if (schema.id && this.hasSchema(schema.id)) {
      const schemaResult = this.validateCredential(credential, schema.id);
      if (!schemaResult.valid) {
        errors.push(...schemaResult.errors.map(err => `Schema ${schema.id}: ${err}`));
      }
    } else if (schema.id) {
      warnings.push(`Referenced schema not available: ${schema.id}`);
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Get all available schema IDs
   */
  getAvailableSchemas(): string[] {
    const builtInSchemas = Object.keys(BUILT_IN_SCHEMAS);
    const customSchemas = Array.from(this.customSchemas.keys());
    return [...builtInSchemas, ...customSchemas];
  }

  /**
   * Get schema by ID
   */
  getSchema(schemaId: string): AnySchema | undefined {
    const validate = this.ajv.getSchema(schemaId);
    return validate?.schema as AnySchema;
  }

  /**
   * Validate data against a specific schema
   */
  validateAgainstSchema(data: any, schemaId: string): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      const validate = this.ajv.getSchema(schemaId);
      if (!validate) {
        errors.push(`Schema not found: ${schemaId}`);
        return { valid: false, errors, warnings };
      }

      const valid = validate(data);
      if (!valid && validate.errors) {
        for (const error of validate.errors) {
          const errorMessage = this.formatError(error);
          errors.push(errorMessage);
        }
      }

      return { valid: errors.length === 0, errors, warnings };
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
export { BUILT_IN_SCHEMAS };