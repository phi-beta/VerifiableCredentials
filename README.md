# W3C Verifiable Credentials TypeScript Implementation

A comprehensive TypeScript implementation of the W3C Verifiable Credentials Data Model v2.0 specification.

## Features

- **Full W3C Compliance**: Implements the W3C Verifiable Credentials Data Model v2.0 specification
- **TypeScript Support**: Full type definitions for all interfaces and classes
- **Complete Role Implementation**: Issuer, Holder, and Verifier roles with comprehensive functionality
- **JSON-LD Context Management**: Built-in context handling with offline support
- **Flexible Validation**: Comprehensive validation engine with customizable options
- **Security Features**: Cryptographic proof support and security management
- **Utility Functions**: Helper functions for common operations

## Installation

```bash
npm install w3c-verifiable-credentials
```

## Quick Start

```typescript
import { Issuer, Holder, Verifier } from 'w3c-verifiable-credentials';

// Create an issuer (e.g., a university)
const university = new Issuer({
  id: 'https://university.edu',
  name: 'Example University'
});

// Issue a credential
const credential = await university.issueCredential({
  credentialSubject: {
    id: 'https://student.example/profile',
    name: 'Alice Smith',
    degree: 'Bachelor of Science'
  },
  type: 'UniversityDegreeCredential'
});

// Create a holder (e.g., a student)
const student = new Holder({
  id: 'https://student.example/profile',
  name: 'Alice Smith'
});

// Store the credential
student.storeCredential(credential);

// Create a presentation
const presentation = await student.createPresentation({
  verifiableCredential: [credential],
  challenge: 'presentation-challenge'
});

// Verify the presentation
const verifier = new Verifier({
  id: 'https://verifier.example',
  trustedIssuers: ['https://university.edu']
});

const result = await verifier.verifyPresentation(presentation);
console.log('Verification result:', result.valid);
```

## Core Components

### Issuer

The `Issuer` class handles credential issuance and management:

```typescript
const issuer = new Issuer({
  id: 'https://issuer.example',
  name: 'Credential Issuer',
  description: 'Issues various types of credentials'
});

// Issue a credential
const credential = await issuer.issueCredential({
  credentialSubject: {
    id: 'https://subject.example',
    // ... credential claims
  },
  type: ['VerifiableCredential', 'CustomCredential'],
  validFrom: '2024-01-01T00:00:00Z',
  validUntil: '2025-01-01T00:00:00Z'
});

// Batch issue multiple credentials
const credentials = await issuer.batchIssueCredentials([
  { credentialSubject: { id: 'subject1', name: 'User 1' } },
  { credentialSubject: { id: 'subject2', name: 'User 2' } }
]);
```

### Holder

The `Holder` class manages credential storage and presentation creation:

```typescript
const holder = new Holder({
  id: 'https://holder.example',
  name: 'Credential Holder'
});

// Store credentials
holder.storeCredential(credential);

// Create presentations
const presentation = await holder.createPresentation({
  verifiableCredential: [credential],
  type: 'JobApplicationPresentation',
  challenge: 'job-app-challenge',
  domain: 'employer.com'
});

// Filter credentials
const degreeCredentials = holder.getCredentialsByType('UniversityDegreeCredential');
const validCredentials = holder.getValidCredentials();
```

### Verifier

The `Verifier` class handles credential and presentation verification:

```typescript
const verifier = new Verifier({
  id: 'https://verifier.example',
  name: 'Credential Verifier',
  trustedIssuers: ['https://trusted-issuer.example']
});

// Verify a credential
const credentialResult = await verifier.verifyCredential(credential, {
  checkExpiration: true,
  checkRevocation: true
});

// Verify a presentation
const presentationResult = await verifier.verifyPresentation(presentation, {
  challenge: 'expected-challenge',
  domain: 'expected-domain'
});
```

### Validation Engine

The `ValidationEngine` provides comprehensive validation capabilities:

```typescript
import { ValidationEngine } from 'w3c-verifiable-credentials';

const validator = new ValidationEngine();

const result = await validator.validateCredential(credential, {
  validateSchema: true,
  validateProof: true,
  validateExpiration: true,
  trustedIssuers: ['https://trusted-issuer.example'],
  allowedTypes: ['UniversityDegreeCredential']
});

console.log('Valid:', result.valid);
console.log('Errors:', result.errors);
console.log('Warnings:', result.warnings);
```

## Context Management

The library includes built-in JSON-LD context management:

```typescript
import { ContextManager, W3C_VC_CONTEXT_V2 } from 'w3c-verifiable-credentials';

const contextManager = new ContextManager();

// Add custom contexts
contextManager.addContext('https://custom.example/context', {
  customProperty: 'https://custom.example/customProperty'
});

// Expand JSON-LD documents
const expanded = await contextManager.expand(credential);

// Validate contexts
const validation = await contextManager.validateContext(credential);
```

## Security Features

The library provides security and cryptographic operations:

```typescript
import { SecurityManager } from 'w3c-verifiable-credentials';

const security = new SecurityManager();

// Generate key pairs
const keyPair = security.generateKeyPair('ed25519');

// Create proofs
const proof = await security.createProof({
  type: 'Ed25519Signature2020',
  verificationMethod: 'https://issuer.example#key-1',
  proofPurpose: 'assertionMethod',
  data: credential
});

// Verify proofs
const isValid = await security.verifyProof(proof, credential, publicKey);
```

## Utility Functions

The library includes various utility functions:

```typescript
import { 
  generateURI, 
  getCurrentDateTime, 
  isValidURI, 
  isCredentialValid,
  filterCredentialsByType 
} from 'w3c-verifiable-credentials';

// Generate unique URIs
const credentialId = generateURI('https://example.com/credentials');

// Get current timestamp
const now = getCurrentDateTime();

// Validate URIs
const valid = isValidURI('https://example.com');

// Check credential validity
const isValid = isCredentialValid(credential);

// Filter credentials
const filtered = filterCredentialsByType(credentials, 'DegreeCredential');
```

## Development

### Building the Project

```bash
npm run build
```

### Running Tests

```bash
npm test
npm run test:watch
npm run test:coverage
```

### Development Mode

```bash
npm run dev
```

## Examples

See the `examples/` directory for complete usage examples:

- `basic-usage.ts` - Comprehensive demonstration including credential issuance, storage, verification, schema validation, and OIDC4VC configuration
- `oidc4vc-demo.ts` - Full end-to-end OIDC4VC workflow with HTTP servers and client interactions

## API Reference

### Types

The library exports comprehensive TypeScript interfaces:

- `VerifiableCredential` - Core credential structure
- `VerifiablePresentation` - Presentation structure  
- `Issuer` - Issuer information interface
- `CredentialSubject` - Subject claims interface
- `Proof` - Cryptographic proof interface
- `ValidationResult` - Validation outcome interface

### Classes

- `Issuer` - Credential issuance and management
- `Holder` - Credential storage and presentation creation
- `Verifier` - Credential and presentation verification
- `ValidationEngine` - Comprehensive validation
- `ContextManager` - JSON-LD context handling
- `SecurityManager` - Cryptographic operations

## Standards Compliance

This implementation follows the W3C Verifiable Credentials Data Model v2.0 specification:

- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model/)
- [W3C Verifiable Credentials Use Cases](https://www.w3.org/TR/vc-use-cases/)
- [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/)

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests.

## License

MIT License - see LICENSE file for details.

## Support

For questions, issues, or contributions, please use the GitHub issue tracker.

## 🌐 OIDC4VC Support

### OpenID Connect for Verifiable Credentials

The implementation now includes support for **OIDC4VC** (OpenID Connect for Verifiable Credentials), enabling modern credential exchange via HTTP APIs:

#### OIDC4VCI (Credential Issuance)
```typescript
import { OIDC4VCIServer, Issuer } from 'w3c-verifiable-credentials';

const issuer = new Issuer({ id: 'https://university.edu', name: 'University' });

const vciServer = new OIDC4VCIServer({
  issuerUrl: 'http://localhost:3001',
  port: 3001,
  supportedCredentialTypes: ['UniversityDegreeCredential'],
  issuer
});

await vciServer.start();
```

#### OIDC4VP (Presentation Verification)
```typescript
import { OIDC4VPServer, Verifier } from 'w3c-verifiable-credentials';

const verifier = new Verifier({ 
  id: 'https://employer.com', 
  trustedIssuers: ['https://university.edu'] 
});

const vpServer = new OIDC4VPServer({
  verifierUrl: 'http://localhost:3002',
  port: 3002,
  verifier,
  clientId: 'employer-verifier',
  redirectUri: 'http://localhost:3002/callback'
});

await vpServer.start();
```

#### OIDC4VC Client
```typescript
import { OIDC4VCClient, Holder } from 'w3c-verifiable-credentials';

const holder = new Holder({ id: 'https://student.example', name: 'Alice' });
const client = new OIDC4VCClient(holder);

// Accept credential offer
const credential = await client.acceptCredentialOffer(credentialOfferUri);

// Submit presentation
const result = await client.submitPresentation(authRequestUri, ['DegreeCredential']);
```

### OIDC4VC Features

- ✅ **Credential Issuance Server (OIDC4VCI)**
  - Well-known metadata endpoints
  - OAuth 2.0 token endpoint
  - Credential issuance endpoint
  - Pre-authorized code flow
  - Multiple credential type support

- ✅ **Presentation Verification Server (OIDC4VP)**
  - Authorization request creation
  - Presentation definition support
  - Direct post response mode
  - Verification result tracking

- ✅ **Client Implementation**
  - Credential offer acceptance
  - Presentation submission
  - HTTP-based credential exchange

### Live Demo

Run the OIDC4VC demo to see the full workflow:

```bash
npm run build
npx ts-node examples/oidc4vc-demo.ts
```

This demonstrates:
1. Starting OIDC4VCI and OIDC4VP servers
2. Creating credential offers
3. Issuing credentials via HTTP API
4. Creating presentation requests
5. Submitting presentations for verification
6. End-to-end OIDC4VC workflow
