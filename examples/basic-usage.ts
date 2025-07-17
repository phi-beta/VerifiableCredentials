/**
 * Example demonstrating the W3C Verifiable Credentials TypeScript implementation
 */

import { 
  Issuer,
  Holder,
  Verifier,
  ValidationEngine,
  SchemaValidator,
  schemaValidator,
  VerifiableCredential,
  VerifiablePresentation,
  generateURI,
  getCurrentDateTime,
  OIDC4VCIServer,
  OIDC4VPServer,
  OIDC4VCClient
} from '../src';

async function main() {
  console.log('🎓 W3C Verifiable Credentials TypeScript Implementation Example\n');

  // 1. Create an Issuer (e.g., a University)
  console.log('1. Creating Issuer (University)...');
  const university = new Issuer({
    id: 'https://university.edu',
    name: 'Example University',
    description: 'A prestigious educational institution'
  });

  // Generate a key pair for the issuer
  console.log('   - Generating cryptographic key pair...');
  const securityManager = (university as any).securityManager;
  await securityManager.generateKeyPair('Ed25519', 'placeholder-key');

  // 2. Create a Holder (e.g., a Student)
  console.log('2. Creating Holder (Student)...');
  const student = new Holder({
    id: 'https://student.example/profile',
    name: 'Alice Smith'
  });

  // Generate a key pair for the holder
  console.log('   - Generating cryptographic key pair...');
  const holderSecurityManager = (student as any).securityManager;
  await holderSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');

  // 3. Create a Verifier (e.g., an Employer)
  console.log('3. Creating Verifier (Employer)...');
  const employer = new Verifier({
    id: 'https://employer.com',
    name: 'Tech Company Inc.',
    trustedIssuers: ['https://university.edu']
  });

  // 4. Issue a Degree Credential
  console.log('4. Issuing Degree Credential...');
  const degreeCredential = await university.issueCredential({
    credentialSubject: {
      id: 'https://student.example/profile',
      name: 'Alice Smith',
      degree: {
        type: 'BachelorDegree',
        name: 'Bachelor of Science in Computer Science',
        degreeSchool: 'School of Computer Science'
      },
      graduationDate: '2024-05-15'
    },
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    validFrom: getCurrentDateTime(),
    validUntil: '2034-05-15T00:00:00Z'
  });

  console.log('✓ Degree credential issued with ID:', degreeCredential.id);

  // 5. Holder stores the credential
  console.log('5. Holder storing credential...');
  student.storeCredential(degreeCredential);
  console.log('✓ Credential stored. Total credentials:', student.listCredentials().length);

  // 6. Create a Presentation for Job Application
  console.log('6. Creating Presentation for Job Application...');
  const jobApplicationPresentation = await student.createPresentation({
    verifiableCredential: [degreeCredential],
    type: ['VerifiablePresentation', 'JobApplicationPresentation'],
    challenge: 'job-application-challenge-123',
    domain: 'employer.com'
  });

  console.log('✓ Presentation created with ID:', jobApplicationPresentation.id);

  // 7. Verifier validates the presentation
  console.log('7. Verifier validating presentation...');
  const verificationResult = await employer.verifyPresentation(jobApplicationPresentation, {
    challenge: 'job-application-challenge-123',
    domain: 'employer.com',
    trustedIssuers: ['https://university.edu']
  });

  console.log('✓ Verification result:');
  console.log('  - Valid:', verificationResult.valid);
  console.log('  - Errors:', verificationResult.errors.length);
  console.log('  - Warnings:', verificationResult.warnings?.length || 0);

  if (verificationResult.errors.length > 0) {
    console.log('  - Error details:', verificationResult.errors);
  }

  // 8. Demonstrate comprehensive validation
  console.log('8. Running comprehensive validation...');
  const validationEngine = new ValidationEngine();
  const comprehensiveResult = await validationEngine.validateCredential(degreeCredential, {
    validateProof: true,
    validateExpiration: true,
    trustedIssuers: ['https://university.edu']
  });

  console.log('✓ Comprehensive validation result:');
  console.log('  - Valid:', comprehensiveResult.valid);
  console.log('  - Errors:', comprehensiveResult.errors.length);
  console.log('  - Warnings:', comprehensiveResult.warnings?.length || 0);

  // 9. Issue another credential (Professional Certification)
  console.log('9. Issuing Professional Certification...');
  const certificationIssuer = new Issuer({
    id: 'https://techcert.org',
    name: 'Tech Certification Authority'
  });

  // Generate a key pair for the certification issuer
  console.log('   - Generating cryptographic key pair...');
  const certSecurityManager = (certificationIssuer as any).securityManager;
  await certSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');

  const certificationCredential = await certificationIssuer.issueCredential({
    credentialSubject: {
      id: 'https://student.example/profile',
      certification: {
        type: 'ProfessionalCertification',
        name: 'Certified Cloud Architect',
        level: 'Professional'
      },
      examDate: '2024-03-20',
      score: 92
    },
    type: ['VerifiableCredential', 'ProfessionalCertificationCredential'],
    validFrom: getCurrentDateTime(),
    validUntil: '2027-03-20T00:00:00Z'
  });

  student.storeCredential(certificationCredential);
  console.log('✓ Professional certification issued and stored');

  // 10. Create a multi-credential presentation
  console.log('10. Creating multi-credential presentation...');
  const multiCredentialPresentation = await student.createPresentation({
    verifiableCredential: [degreeCredential, certificationCredential],
    type: ['VerifiablePresentation', 'ProfessionalProfilePresentation']
  });

  console.log('✓ Multi-credential presentation created');
  console.log('   - Contains', multiCredentialPresentation.verifiableCredential?.length, 'credentials');

  // 11. Demonstrate filtering utilities
  console.log('11. Demonstrating credential filtering...');
  const allCredentials = student.listCredentials();
  const degreeCredentials = student.getCredentialsByType('UniversityDegreeCredential');
  const certificationCredentials = student.getCredentialsByType('ProfessionalCertificationCredential');

  console.log('✓ Credential filtering results:');
  console.log('  - Total credentials:', allCredentials.length);
  console.log('  - Degree credentials:', degreeCredentials.length);
  console.log('  - Certification credentials:', certificationCredentials.length);

  // 12. Export and import credentials
  console.log('12. Demonstrating export/import...');
  const exportedCredentials = student.exportCredentials();
  
  const newHolder = new Holder({
    id: 'https://newstudent.example/profile',
    name: 'Bob Johnson'
  });
  
  newHolder.importCredentials(exportedCredentials);
  console.log('✓ Credentials exported and imported successfully');
  console.log('   - New holder has', newHolder.listCredentials().length, 'credentials');

  // 13. Demonstrate schema validation
  console.log('13. Demonstrating schema validation...');
  
  // List available schemas
  const availableSchemas = schemaValidator.getAvailableSchemas();
  console.log('✓ Available schemas:', availableSchemas);
  
  // Validate degree credential against its schema
  const degreeSchemaResult = schemaValidator.validateCredential(degreeCredential);
  console.log('✓ Degree credential schema validation:');
  console.log('   - Valid:', degreeSchemaResult.valid);
  console.log('   - Errors:', degreeSchemaResult.errors.length);
  console.log('   - Warnings:', degreeSchemaResult.warnings?.length || 0);
  
  if (degreeSchemaResult.errors.length > 0) {
    console.log('   - Error details:', degreeSchemaResult.errors);
  }
  
  // Validate certification credential against its schema
  const certSchemaResult = schemaValidator.validateCredential(certificationCredential);
  console.log('✓ Certification credential schema validation:');
  console.log('   - Valid:', certSchemaResult.valid);
  console.log('   - Errors:', certSchemaResult.errors.length);
  console.log('   - Warnings:', certSchemaResult.warnings?.length || 0);
  
  // Validate presentation against its schema
  const presentationSchemaResult = schemaValidator.validatePresentation(multiCredentialPresentation);
  console.log('✓ Presentation schema validation:');
  console.log('   - Valid:', presentationSchemaResult.valid);
  console.log('   - Errors:', presentationSchemaResult.errors.length);
  console.log('   - Warnings:', presentationSchemaResult.warnings?.length || 0);
  
  // 14. Demonstrate custom schema validation
  console.log('14. Demonstrating custom schema validation...');
  
  // Create a custom schema validator instance
  const customValidator = new SchemaValidator();
  
  // Add a custom schema for driver's license
  const driverLicenseSchema = {
    $id: 'DriverLicenseCredential',
    $schema: 'http://json-schema.org/draft-07/schema#',
    allOf: [
      { $ref: 'VerifiableCredential' },
      {
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            required: ['id', 'name', 'licenseNumber', 'licenseClass'],
            properties: {
              id: { type: 'string', format: 'uri' },
              name: { type: 'string' },
              licenseNumber: { type: 'string' },
              licenseClass: { type: 'string' },
              issuingState: { type: 'string' },
              expirationDate: { type: 'string', format: 'date' }
            }
          }
        }
      }
    ]
  };
  
  customValidator.addSchema('DriverLicenseCredential', driverLicenseSchema);
  console.log('✓ Custom driver license schema added');
  
  // Create a driver license credential
  const dmv = new Issuer({
    id: 'https://dmv.state.gov',
    name: 'State Department of Motor Vehicles'
  });

  // Generate a key pair for the DMV issuer
  console.log('   - Generating cryptographic key pair for DMV...');
  const dmvSecurityManager = (dmv as any).securityManager;
  await dmvSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');
  
  const driverLicenseCredential = await dmv.issueCredential({
    credentialSubject: {
      id: 'https://student.example/profile',
      name: 'Alice Smith',
      licenseNumber: 'DL123456789',
      licenseClass: 'C',
      issuingState: 'California',
      expirationDate: '2028-05-15'
    },
    type: ['VerifiableCredential', 'DriverLicenseCredential'],
    validFrom: getCurrentDateTime(),
    validUntil: '2028-05-15T23:59:59Z'
  });
  
  // Validate the driver license credential
  const driverLicenseResult = customValidator.validateCredential(driverLicenseCredential);
  console.log('✓ Driver license credential schema validation:');
  console.log('   - Valid:', driverLicenseResult.valid);
  console.log('   - Errors:', driverLicenseResult.errors.length);
  console.log('   - Warnings:', driverLicenseResult.warnings?.length || 0);
  
  // 15. Demonstrate schema validation with invalid data
  console.log('15. Demonstrating schema validation with invalid data...');
  
  // Create an invalid credential (missing required fields)
  const invalidCredential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    // Missing issuer and credentialSubject
    id: generateURI(),
    validFrom: getCurrentDateTime()
  } as VerifiableCredential;
  
  const invalidResult = schemaValidator.validateCredential(invalidCredential);
  console.log('✓ Invalid credential schema validation:');
  console.log('   - Valid:', invalidResult.valid);
  console.log('   - Errors:', invalidResult.errors.length);
  console.log('   - Error details:', invalidResult.errors);
  
  // 16. Demonstrate schema validation against specific schema
  console.log('16. Demonstrating validation against specific schema...');
  
  // Validate degree credential against the base VerifiableCredential schema
  const baseSchemaResult = schemaValidator.validateCredential(degreeCredential, 'VerifiableCredential');
  console.log('✓ Degree credential against base VC schema:');
  console.log('   - Valid:', baseSchemaResult.valid);
  console.log('   - Errors:', baseSchemaResult.errors.length);
  
  // Try to validate against a non-existent schema
  const nonExistentResult = schemaValidator.validateCredential(degreeCredential, 'NonExistentSchema');
  console.log('✓ Validation against non-existent schema:');
  console.log('   - Valid:', nonExistentResult.valid);
  console.log('   - Errors:', nonExistentResult.errors.length);
  console.log('   - Error details:', nonExistentResult.errors);

  // 17. Demonstrate OIDC4VC (OpenID Connect for Verifiable Credentials)
  console.log('17. Demonstrating OIDC4VC configuration and concepts...');
  
  // Setup OIDC4VCI Server for credential issuance
  const oidcIssuer = new Issuer({
    id: 'https://oidc-university.edu',
    name: 'OIDC University',
    description: 'University with OIDC4VC support'
  });

  // Generate key pair for OIDC issuer
  const oidcIssuerSecurityManager = (oidcIssuer as any).securityManager;
  await oidcIssuerSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');

  const oidcVciServer = new OIDC4VCIServer({
    issuerUrl: 'https://oidc-university.edu',
    port: 8080,
    supportedCredentialTypes: ['UniversityDegreeCredential', 'ProfessionalCertificationCredential'],
    issuer: oidcIssuer
  });

  console.log('✓ OIDC4VCI Server configured for credential issuance');

  // Setup OIDC4VP Server for credential presentation
  const oidcVerifier = new Verifier({
    id: 'https://oidc-employer.com',
    name: 'OIDC Employer',
    trustedIssuers: ['https://oidc-university.edu']
  });

  const oidcVpServer = new OIDC4VPServer({
    verifierUrl: 'https://oidc-employer.com',
    port: 8081,
    verifier: oidcVerifier,
    clientId: 'oidc-employer-client',
    redirectUri: 'https://oidc-employer.com/callback'
  });

  console.log('✓ OIDC4VP Server configured for credential presentation');

  // Create OIDC4VC Client (representing the wallet/holder)
  const oidcClient = new OIDC4VCClient(student);
  console.log('✓ OIDC4VC Client created for wallet interaction');

  // Demonstrate OIDC4VC configuration and capabilities
  console.log('   - OIDC4VC Server Configurations:');
  console.log('     • Issuer URL: https://oidc-university.edu');
  console.log('     • Supported Credential Types: UniversityDegreeCredential, ProfessionalCertificationCredential');
  console.log('     • Verifier URL: https://oidc-employer.com');
  console.log('     • Client ID: oidc-employer-client');

  // Show what OIDC4VC enables
  console.log('   - OIDC4VC Capabilities:');
  console.log('     • HTTP-based credential issuance (OIDC4VCI)');
  console.log('     • HTTP-based credential presentation (OIDC4VP)');
  console.log('     • Integration with existing OAuth 2.0/OpenID Connect infrastructure');
  console.log('     • QR code and deep link support for mobile wallets');
  console.log('     • Pre-authorized code flow for streamlined issuance');
  console.log('     • Presentation definition for fine-grained credential requests');

  // Show credential offer structure
  console.log('   - Example Credential Offer Structure:');
  const exampleCredentialOffer = {
    credential_issuer: 'https://oidc-university.edu',
    credentials: ['UniversityDegreeCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'demo-pre-auth-code-123',
        user_pin_required: false
      }
    }
  };
  console.log('     ', JSON.stringify(exampleCredentialOffer, null, 6));

  // Show presentation request structure
  console.log('   - Example Presentation Request Structure:');
  const examplePresentationRequest = {
    client_id: 'oidc-employer-client',
    response_type: 'vp_token',
    scope: 'openid',
    response_mode: 'direct_post',
    presentation_definition: {
      id: 'job-application-requirements',
      input_descriptors: [{
        id: 'university-degree',
        constraints: {
          fields: [{
            path: ['$.type'],
            filter: {
              type: 'array',
              contains: { const: 'UniversityDegreeCredential' }
            }
          }]
        }
      }]
    }
  };
  console.log('     ', JSON.stringify(examplePresentationRequest, null, 6));

  // Demonstrate endpoints available
  console.log('   - Available OIDC4VC Endpoints:');
  console.log('     • Issuer Metadata: /.well-known/openid_credential_issuer');
  console.log('     • Token Endpoint: /token');
  console.log('     • Credential Endpoint: /credential');
  console.log('     • Verifier Metadata: /.well-known/openid_credential_verifier');
  console.log('     • Authorization Endpoint: /authorize');
  console.log('     • Presentation Endpoint: /presentation');

  console.log('✓ OIDC4VC demonstration completed');
  console.log('   - Servers configured for HTTP-based credential exchange');
  console.log('   - Client ready for wallet interactions');
  console.log('   - See examples/oidc4vc-demo.ts for full end-to-end HTTP workflow');

  console.log('\n🎉 Example completed successfully!');
}

// Run the example
main().catch(error => {
  console.error('❌ Example failed:', error);
  process.exit(1);
});
