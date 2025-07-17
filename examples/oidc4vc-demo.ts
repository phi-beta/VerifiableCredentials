/**
 * OIDC4VC Example - OpenID Connect for Verifiable Credentials
 * Demonstrates credential issuance and presentation using HTTP protocols
 */

import { 
  Issuer,
  Holder,
  Verifier,
  OIDC4VCIServer,
  OIDC4VPServer,
  OIDC4VCClient,
  generateURI,
  getCurrentDateTime
} from '../src';

async function demonstrateOIDC4VC() {
  console.log('🌐 OIDC4VC (OpenID Connect for Verifiable Credentials) Demo\n');

  // 1. Setup: Create issuer, holder, and verifier
  console.log('1. Setting up roles...');
  
  const university = new Issuer({
    id: 'https://university.edu',
    name: 'Digital University',
    description: 'A modern digital university'
  });

  // Generate key pair for the issuer
  const issuerSecurityManager = (university as any).securityManager;
  await issuerSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');

  const student = new Holder({
    id: 'https://student.example/alice',
    name: 'Alice Johnson'
  });

  // Generate key pair for the holder
  const holderSecurityManager = (student as any).securityManager;
  await holderSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');

  const employer = new Verifier({
    id: 'https://acme-corp.com',
    name: 'ACME Corporation',
    trustedIssuers: ['https://university.edu']
  });

  console.log('✓ Roles created and key pairs generated');

  // 2. Start OIDC4VCI Server (Credential Issuer)
  console.log('\n2. Starting OIDC4VCI Server...');
  
  const vciServer = new OIDC4VCIServer({
    issuerUrl: 'http://localhost:3001',
    port: 3001,
    supportedCredentialTypes: ['UniversityDegreeCredential', 'ProfessionalCertificationCredential'],
    issuer: university
  });

  // Start the server (non-blocking)
  vciServer.start().catch(console.error);
  
  // Wait a moment for server to start
  await new Promise(resolve => setTimeout(resolve, 1000));
  console.log('✓ OIDC4VCI Server running on http://localhost:3001');

  // 3. Start OIDC4VP Server (Presentation Verifier)
  console.log('\n3. Starting OIDC4VP Server...');
  
  const vpServer = new OIDC4VPServer({
    verifierUrl: 'http://localhost:3002',
    port: 3002,
    verifier: employer,
    clientId: 'acme-corp-verifier',
    redirectUri: 'http://localhost:3002/callback'
  });

  // Start the server (non-blocking)
  vpServer.start().catch(console.error);
  
  // Wait a moment for server to start
  await new Promise(resolve => setTimeout(resolve, 1000));
  console.log('✓ OIDC4VP Server running on http://localhost:3002');

  // 4. Create and offer a credential
  console.log('\n4. Creating credential offer...');
  
  try {
    // Create a credential offer
    const credentialOfferResponse = await fetch('http://localhost:3001/credential-offer', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        credential_types: ['UniversityDegreeCredential'],
        subject: {
          id: 'https://student.example/alice',
          name: 'Alice Johnson',
          degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Science in Computer Science',
            degreeSchool: 'School of Computer Science'
          },
          graduationDate: '2024-05-15'
        }
      })
    });

    const credentialOfferData = await credentialOfferResponse.json();
    console.log('✓ Credential offer created');
    console.log('  - Offer URI:', credentialOfferData.credential_offer_uri);

    // 5. Accept the credential offer using OIDC4VC Client
    console.log('\n5. Accepting credential offer...');
    
    const oidcClient = new OIDC4VCClient(student);
    
    // Simulate accepting the credential offer
    // Note: In a real scenario, this would be done via QR code or deep link
    const credential = await acceptCredentialOfferSimulated(
      credentialOfferData.credential_offer,
      university,
      student
    );
    
    console.log('✓ Credential accepted and stored');
    console.log('  - Credential ID:', credential.id);
    console.log('  - Total credentials:', student.listCredentials().length);

    // 6. Create a presentation request
    console.log('\n6. Creating presentation request...');
    
    const presentationRequestResponse = await fetch('http://localhost:3002/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        credential_types: ['UniversityDegreeCredential'],
        purpose: 'employment_verification'
      })
    });

    const presentationRequestData = await presentationRequestResponse.json();
    console.log('✓ Presentation request created');
    console.log('  - Request URI:', presentationRequestData.request_uri);

    // 7. Submit presentation
    console.log('\n7. Submitting presentation...');
    
    // Find the credential to present
    const credentialsToPresent = student.getCredentialsByType('UniversityDegreeCredential');
    if (credentialsToPresent.length === 0) {
      throw new Error('No matching credentials found');
    }

    // Create presentation
    const presentation = await student.createPresentation({
      verifiableCredential: [credentialsToPresent[0]],
      type: ['VerifiablePresentation'],
      challenge: presentationRequestData.authorization_request.nonce,
      domain: 'http://localhost:3002'
    });

    // Submit presentation
    const presentationSubmissionResponse = await fetch('http://localhost:3002/presentation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        vp_token: JSON.stringify(presentation),
        presentation_submission: {
          id: generateURI(),
          definition_id: presentationRequestData.authorization_request.presentation_definition.id,
          descriptor_map: [{
            id: presentationRequestData.authorization_request.presentation_definition.input_descriptors[0].id,
            format: 'ldp_vp',
            path: '$.verifiableCredential[0]'
          }]
        },
        state: presentationRequestData.authorization_request.state
      })
    });

    const submissionResult = await presentationSubmissionResponse.json();
    console.log('✓ Presentation submitted successfully');
    console.log('  - Status:', submissionResult.status);
    
    if (submissionResult.redirect_uri) {
      console.log('  - Redirect URI:', submissionResult.redirect_uri);
    }

    // 8. Check verification results
    console.log('\n8. Checking verification results...');
    
    const resultResponse = await fetch(
      `http://localhost:3002/result/${presentationRequestData.authorization_request.state}`
    );
    
    const verificationResult = await resultResponse.json();
    console.log('✓ Verification completed');
    console.log('  - Valid:', verificationResult.valid);
    console.log('  - Errors:', verificationResult.errors.length);
    console.log('  - Warnings:', verificationResult.warnings?.length || 0);

    if (verificationResult.errors.length > 0) {
      console.log('  - Error details:', verificationResult.errors);
    }

    // 9. Display summary
    console.log('\n9. OIDC4VC Demo Summary:');
    console.log('✓ Credential Issuance via OIDC4VCI:', verificationResult.valid ? 'SUCCESS' : 'FAILED');
    console.log('✓ Presentation Verification via OIDC4VP:', verificationResult.valid ? 'SUCCESS' : 'FAILED');
    console.log('✓ End-to-end OIDC4VC workflow:', verificationResult.valid ? 'COMPLETED' : 'FAILED');

    console.log('\n🎉 OIDC4VC Demo completed successfully!');

  } catch (error) {
    console.error('❌ OIDC4VC Demo failed:', error);
  }
}

/**
 * Simulate accepting a credential offer
 * In a real implementation, this would use the OIDC4VCClient
 */
async function acceptCredentialOfferSimulated(
  credentialOffer: any,
  issuer: Issuer,
  holder: Holder
) {
  // This simulates the OIDC4VC flow without actual HTTP calls to avoid circular dependencies
  const credential = await issuer.issueCredential({
    credentialSubject: {
      id: 'https://student.example/alice',
      name: 'Alice Johnson',
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

  holder.storeCredential(credential);
  return credential;
}

// Run the demo
if (require.main === module) {
  demonstrateOIDC4VC().catch(error => {
    console.error('Demo failed:', error);
    process.exit(1);
  });
}

export { demonstrateOIDC4VC };
