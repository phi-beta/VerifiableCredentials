/**
 * Test and demonstrate the comprehensive utility functions
 */

import { 
  generateURI, 
  getCurrentDateTime, 
  isValidURI,
  isValidDateTime,
  getIssuerURI,
  hasCredentialType,
  isCredentialValid,
  filterCredentialsByType,
  filterCredentialsByIssuer,
  getCredentialStatistics,
  generateCredentialSummaryReport,
  parseDID,
  generateDID,
  generateCredentialFingerprint
} from './src/utils';

import { Issuer } from './src/roles/issuer';

async function demonstrateUtilityFunctions() {
  console.log('🔧 Demonstrating Comprehensive Utility Functions\n');

  // 1. URI and DateTime utilities
  console.log('1. URI and DateTime Utilities:');
  const uri = generateURI();
  const currentTime = getCurrentDateTime();
  console.log(`   Generated URI: ${uri}`);
  console.log(`   Current DateTime: ${currentTime}`);
  console.log(`   URI Valid: ${isValidURI(uri)}`);
  console.log(`   DateTime Valid: ${isValidDateTime(currentTime)}\n`);

  // 2. DID utilities
  console.log('2. DID Utilities:');
  const testDID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const didComponents = parseDID(testDID);
  const generatedDID = generateDID('key');
  console.log(`   Test DID: ${testDID}`);
  console.log(`   Parsed DID:`, didComponents);
  console.log(`   Generated DID: ${generatedDID}\n`);

  // 3. Create test credentials for filtering and statistics
  console.log('3. Creating Test Credentials...');
  const university = new Issuer({
    id: 'https://university.edu',
    name: 'Test University'
  });

  // Generate key pair for the issuer
  const securityManager = (university as any).securityManager;
  await securityManager.generateKeyPair('Ed25519', 'placeholder-key');

  const credential1 = await university.issueCredential({
    credentialSubject: {
      id: 'https://student1.example',
      name: 'Alice Smith',
      degree: 'Bachelor of Science'
    },
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    validFrom: getCurrentDateTime(),
    validUntil: '2025-12-31T23:59:59Z'
  });

  const credential2 = await university.issueCredential({
    credentialSubject: {
      id: 'https://student2.example',
      name: 'Bob Johnson',
      certification: 'Professional Certification'
    },
    type: ['VerifiableCredential', 'ProfessionalCertificationCredential'],
    validFrom: getCurrentDateTime(),
    validUntil: '2026-06-30T23:59:59Z'
  });

  const expiredCredential = await university.issueCredential({
    credentialSubject: {
      id: 'https://student3.example',
      name: 'Charlie Brown',
      license: 'Driver License'
    },
    type: ['VerifiableCredential', 'DriverLicenseCredential'],
    validFrom: '2020-01-01T00:00:00Z',
    validUntil: '2023-01-01T00:00:00Z' // Expired
  });

  const credentials = [credential1, credential2, expiredCredential];
  console.log(`   Created ${credentials.length} test credentials\n`);

  // 4. Demonstrate filtering functions
  console.log('4. Credential Filtering:');
  const degreeCredentials = filterCredentialsByType(credentials, 'UniversityDegreeCredential');
  const universityCredentials = filterCredentialsByIssuer(credentials, 'https://university.edu');
  console.log(`   Degree credentials: ${degreeCredentials.length}`);
  console.log(`   University credentials: ${universityCredentials.length}\n`);

  // 5. Demonstrate credential analysis
  console.log('5. Credential Analysis:');
  credentials.forEach((cred, index) => {
    const types = cred.type || [];
    const issuer = getIssuerURI(cred);
    const valid = isCredentialValid(cred);
    const fingerprint = generateCredentialFingerprint(cred);
    
    console.log(`   Credential ${index + 1}:`);
    console.log(`     Types: ${Array.isArray(types) ? types.join(', ') : types}`);
    console.log(`     Issuer: ${issuer}`);
    console.log(`     Valid: ${valid}`);
    console.log(`     Fingerprint: ${fingerprint}`);
  });
  console.log();

  // 6. Demonstrate statistics
  console.log('6. Credential Statistics:');
  const stats = getCredentialStatistics(credentials);
  console.log(`   Total: ${stats.total}`);
  console.log(`   Valid: ${stats.valid}`);
  console.log(`   Expired: ${stats.expired}`);
  console.log(`   Types: ${Array.from(stats.byType.keys()).join(', ')}`);
  console.log(`   Issuers: ${Array.from(stats.byIssuer.keys()).join(', ')}\n`);

  // 7. Generate summary report
  console.log('7. Summary Report:');
  const report = generateCredentialSummaryReport(credentials);
  console.log(report);

  console.log('✅ Utility Functions Demonstration Complete!\n');
}

// Run the demonstration
demonstrateUtilityFunctions().catch(error => {
  console.error('❌ Demonstration failed:', error);
  process.exit(1);
});
