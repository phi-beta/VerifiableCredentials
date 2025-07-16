/**
 * Tests for the ValidationEngine
 */

import { ValidationEngine } from '../validation';
import { VerifiableCredential } from '../types';
import { W3C_VC_CONTEXT_V2 } from '../context';

describe('ValidationEngine', () => {
  let validationEngine: ValidationEngine;
  let validCredential: VerifiableCredential;

  beforeEach(() => {
    validationEngine = new ValidationEngine();
    
    validCredential = {
      '@context': [W3C_VC_CONTEXT_V2],
      id: 'https://example.com/credentials/123',
      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      issuer: 'https://university.edu',
      validFrom: '2024-01-01T00:00:00Z',
      validUntil: '2030-01-01T00:00:00Z', // Future date
      credentialSubject: {
        id: 'https://student.example/profile',
        name: 'Alice Smith',
        degree: 'Bachelor of Science'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'https://university.edu#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'test-proof-value'
      }
    };
  });

  test('should validate a valid credential', async () => {
    const result = await validationEngine.validateCredential(validCredential);
    
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  test('should detect missing required fields', async () => {
    const invalidCredential = {
      '@context': [W3C_VC_CONTEXT_V2],
      type: ['VerifiableCredential']
      // Missing issuer and credentialSubject
    } as VerifiableCredential;

    const result = await validationEngine.validateCredential(invalidCredential);
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Missing required field: issuer');
    expect(result.errors).toContain('Missing required field: credentialSubject');
  });

  test('should detect invalid type', async () => {
    const invalidCredential = {
      ...validCredential,
      type: ['InvalidType'] // Missing VerifiableCredential type
    };

    const result = await validationEngine.validateCredential(invalidCredential);
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Type must include VerifiableCredential');
  });

  test('should detect expired credential', async () => {
    const expiredCredential = {
      ...validCredential,
      validUntil: '2020-01-01T00:00:00Z' // Expired
    };

    const result = await validationEngine.validateCredential(expiredCredential);
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Credential has expired');
  });

  test('should detect not-yet-valid credential', async () => {
    const futureCredential = {
      ...validCredential,
      validFrom: '2030-01-01T00:00:00Z' // Future date
    };

    const result = await validationEngine.validateCredential(futureCredential);
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Credential is not yet valid');
  });

  test('should validate trusted issuer', async () => {
    const trustedIssuers = ['https://university.edu'];
    
    const result = await validationEngine.validateCredential(validCredential, {
      trustedIssuers
    });
    
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  test('should reject untrusted issuer', async () => {
    const trustedIssuers = ['https://other-university.edu'];
    
    const result = await validationEngine.validateCredential(validCredential, {
      trustedIssuers
    });
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Issuer https://university.edu is not in trusted issuers list');
  });

  test('should validate allowed types', async () => {
    const allowedTypes = ['UniversityDegreeCredential'];
    
    const result = await validationEngine.validateCredential(validCredential, {
      allowedTypes
    });
    
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  test('should reject disallowed types', async () => {
    const allowedTypes = ['ProfessionalCertification'];
    
    const result = await validationEngine.validateCredential(validCredential, {
      allowedTypes
    });
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Credential type must be one of: ProfessionalCertification');
  });

  test('should validate missing context', async () => {
    const noContextCredential = {
      ...validCredential,
      '@context': undefined
    } as any;

    const result = await validationEngine.validateCredential(noContextCredential);
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Missing @context property');
  });
});
