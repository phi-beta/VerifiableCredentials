/**
 * Enhanced Validation Engine Demo
 * Demonstrates the comprehensive validation capabilities
 */

import { ValidationEngine } from '../src/validation';
import { Issuer } from '../src/roles/issuer';
import { Holder } from '../src/roles/holder';
import { VerifiableCredential, VerifiablePresentation } from '../src/types';
import { schemaValidator } from '../src/schema';
import { SecurityManager } from '../src/security';

async function demonstrateEnhancedValidation() {
  console.log('🔍 Enhanced Validation Engine Demo');
  console.log('===================================\n');

  const validationEngine = new ValidationEngine();
  const issuer = new Issuer({ 
    id: 'https://university.edu',
    name: 'University of Example'
  });
  const holder = new Holder({
    id: 'https://student.example/profile',
    name: 'Alice Smith'
  });

  // Set up security manager for key generation
  const securityManager = new SecurityManager();
  console.log('Setting up cryptographic keys...');
  await securityManager.generateKeyPair('Ed25519', 'issuer-key-1');
  await securityManager.generateKeyPair('Ed25519', 'holder-key-1');

  // 1. Create and validate a comprehensive credential
  console.log('1. Creating and validating a comprehensive credential...');
  
  // Create a credential manually for validation demo (bypassing signing)
  const credential: VerifiableCredential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: 'https://example.com/credentials/123',
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: 'https://university.edu',
    validFrom: new Date().toISOString(),
    validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year from now
    credentialSubject: {
      id: 'https://student.example/profile',
      name: 'Alice Smith',
      studentId: 'STU123456',
      degree: {
        type: 'Bachelor of Science',
        name: 'Computer Science',
        gpa: 3.8,
        graduationDate: '2024-05-15'
      },
      achievements: [
        'Dean\'s List',
        'Magna Cum Laude'
      ]
    },
    credentialSchema: {
      id: 'UniversityDegreeCredential',
      type: 'JsonSchemaValidator2018'
    },
    evidence: [
      {
        type: ['DocumentVerification'],
        verifier: 'https://university.edu/registrar',
        evidenceDocument: 'Official Transcript'
      }
    ],
    termsOfUse: [
      {
        type: 'IssuerPolicy',
        policy: 'https://university.edu/credential-policy'
      }
    ],
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: 'https://university.edu#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'demo-proof-value-for-validation-testing'
    }
  };

  console.log('✅ Credential created successfully');

  // 2. Perform comprehensive validation
  console.log('\n2. Performing comprehensive validation...');
  
  const validationResult = await validationEngine.validateCredential(credential, {
    validateExpiration: true,
    validateSchema: true,
    validateProof: false, // Skip cryptographic validation for demo
    allowedTypes: ['UniversityDegreeCredential'],
    trustedIssuers: ['https://university.edu'],
    requiredFields: ['credentialSubject.name', 'credentialSubject.degree']
  });

  console.log('Validation Result:', {
    valid: validationResult.valid,
    errorCount: validationResult.errors.length,
    warningCount: validationResult.warnings?.length || 0
  });

  if (validationResult.errors.length > 0) {
    console.log('❌ Validation Errors:');
    validationResult.errors.forEach(error => console.log(`  - ${error}`));
  }

  if (validationResult.warnings && validationResult.warnings.length > 0) {
    console.log('⚠️  Validation Warnings:');
    validationResult.warnings.forEach(warning => console.log(`  - ${warning}`));
  }

  // 3. Detailed validation report
  console.log('\n3. Generating detailed validation report...');
  
  const detailedReport = await validationEngine.validateWithDetailedReport(credential, {
    validateProof: false
  });

  console.log('Detailed Validation Report:');
  console.log(`- Overall Valid: ${detailedReport.valid}`);
  console.log(`- Context Valid: ${detailedReport.details.context.valid}`);
  console.log(`- Structure Valid: ${detailedReport.details.structure.valid}`);
  console.log(`- Subject Valid: ${detailedReport.details.subject.valid}`);
  console.log(`- Temporal Valid: ${detailedReport.details.temporal.valid}`);
  console.log(`- Evidence Valid: ${detailedReport.details.evidence.valid}`);
  console.log(`- Terms of Use Valid: ${detailedReport.details.termsOfUse.valid}`);

  // 4. Schema validation demo
  console.log('\n4. Demonstrating schema validation...');
  
  const schemaValidationResult = await validationEngine.validateCredentialWithSchemas(
    credential,
    ['VerifiableCredential', 'UniversityDegreeCredential']
  );

  console.log('Schema Validation Result:', {
    valid: schemaValidationResult.valid,
    errorCount: schemaValidationResult.errors.length,
    warningCount: schemaValidationResult.warnings?.length || 0
  });

  // 5. Subject validation demo
  console.log('\n5. Demonstrating credential subject validation...');
  
  const subjectValidationResult = validationEngine.validateCredentialSubject(credential);
  
  console.log('Subject Validation Result:', {
    valid: subjectValidationResult.valid,
    errorCount: subjectValidationResult.errors.length,
    warningCount: subjectValidationResult.warnings?.length || 0
  });

  // 6. Create and validate a presentation
  console.log('\n6. Creating and validating a presentation...');
  
  holder.storeCredential(credential);
  
  // Get stored credentials for presentation
  const storedCredentials = holder.listCredentials();
  
  const presentation = await holder.createPresentation({
    context: ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    challenge: 'test-challenge-123',
    domain: 'https://verifier.example.com'
  });

  // Manually add credentials to presentation for demo
  (presentation as any).verifiableCredential = storedCredentials;

  const presentationValidationResult = await validationEngine.validatePresentation(presentation, {
    validateProof: false // Skip cryptographic validation for demo
  });

  console.log('Presentation Validation Result:', {
    valid: presentationValidationResult.valid,
    errorCount: presentationValidationResult.errors.length,
    warningCount: presentationValidationResult.warnings?.length || 0
  });

  // 7. Demonstrate validation with errors
  console.log('\n7. Demonstrating validation with intentional errors...');
  
  const invalidCredential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'], // Missing required type
    // Missing issuer
    credentialSubject: {
      // Missing subject data
    },
    validFrom: '2030-01-01T00:00:00Z', // Future date - not yet valid
    validUntil: '2020-01-01T00:00:00Z', // Past date - expired
    proof: {
      // Incomplete proof
      type: 'Ed25519Signature2020'
      // Missing other required fields
    }
  } as VerifiableCredential;

  const errorValidationResult = await validationEngine.validateCredential(invalidCredential, {
    validateProof: false,
    allowedTypes: ['ProfessionalCertification'], // Disallowed type
    trustedIssuers: ['https://trusted.issuer'] // Untrusted issuer
  });

  console.log('Invalid Credential Validation Result:', {
    valid: errorValidationResult.valid,
    errorCount: errorValidationResult.errors.length
  });

  console.log('❌ Errors found in invalid credential:');
  errorValidationResult.errors.forEach(error => console.log(`  - ${error}`));

  // 8. Available schemas
  console.log('\n8. Available schemas for validation...');
  
  const availableSchemas = schemaValidator.getAvailableSchemas();
  console.log('Available Schema IDs:');
  availableSchemas.forEach(schemaId => console.log(`  - ${schemaId}`));

  console.log('\n🎉 Enhanced Validation Engine Demo Complete!');
  console.log('\nKey Features Demonstrated:');
  console.log('✅ Comprehensive credential validation');
  console.log('✅ Detailed validation reporting');
  console.log('✅ Schema validation');
  console.log('✅ Subject validation');
  console.log('✅ Presentation validation');
  console.log('✅ Error detection and reporting');
  console.log('✅ Temporal validation');
  console.log('✅ Evidence validation');
  console.log('✅ Terms of use validation');
  console.log('✅ Type and issuer validation');
}

// Run the demo
if (require.main === module) {
  demonstrateEnhancedValidation().catch(console.error);
}

export { demonstrateEnhancedValidation };
