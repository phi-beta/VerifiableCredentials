/**
 * Example demonstrating the W3C Verifiable Credentials TypeScript implementation
 */

import { 
  Issuer,
  Holder,
  Verifier,
  ValidationEngine,
  VerifiableCredential,
  VerifiablePresentation,
  generateURI,
  getCurrentDateTime
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

  // 2. Create a Holder (e.g., a Student)
  console.log('2. Creating Holder (Student)...');
  const student = new Holder({
    id: 'https://student.example/profile',
    name: 'Alice Smith'
  });

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

  console.log('\n🎉 Example completed successfully!');
}

// Run the example
main().catch(error => {
  console.error('❌ Example failed:', error);
  process.exit(1);
});
