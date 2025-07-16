/**
 * Tests for the Issuer class
 */

import { Issuer } from '../issuer';
import { W3C_VC_CONTEXT_V2 } from '../../context';

describe('Issuer', () => {
  let issuer: Issuer;

  beforeEach(() => {
    issuer = new Issuer({
      id: 'https://university.edu',
      name: 'Example University',
      description: 'A test university'
    });
  });

  test('should create an issuer with correct properties', () => {
    const issuerInfo = issuer.getIssuerInfo();
    expect(issuerInfo.id).toBe('https://university.edu');
    expect(issuerInfo.name).toBe('Example University');
    expect(issuerInfo.description).toBe('A test university');
  });

  test('should issue a basic credential', async () => {
    const credential = await issuer.issueCredential({
      credentialSubject: {
        id: 'https://student.example/profile',
        name: 'Alice Smith',
        degree: 'Bachelor of Science'
      },
      type: 'UniversityDegreeCredential'
    });

    expect(credential).toBeDefined();
    expect(credential['@context']).toContain(W3C_VC_CONTEXT_V2);
    expect(credential.type).toContain('VerifiableCredential');
    expect(credential.type).toContain('UniversityDegreeCredential');
    expect(credential.issuer).toEqual(issuer.getIssuerInfo());
    expect(credential.credentialSubject).toEqual({
      id: 'https://student.example/profile',
      name: 'Alice Smith',
      degree: 'Bachelor of Science'
    });
    expect(credential.proof).toBeDefined();
  });

  test('should issue a credential with custom ID', async () => {
    const customId = 'https://credentials.example/123';
    const credential = await issuer.issueCredential({
      id: customId,
      credentialSubject: {
        id: 'https://student.example/profile',
        name: 'Bob Johnson'
      }
    });

    expect(credential.id).toBe(customId);
  });

  test('should issue a credential with expiration', async () => {
    const expirationDate = '2025-12-31T23:59:59Z';
    const credential = await issuer.issueCredential({
      credentialSubject: {
        id: 'https://student.example/profile',
        name: 'Charlie Brown'
      },
      validUntil: expirationDate
    });

    expect(credential.validUntil).toBe(expirationDate);
  });

  test('should batch issue multiple credentials', async () => {
    const credentialRequests = [
      {
        credentialSubject: {
          id: 'https://student1.example/profile',
          name: 'Student One'
        }
      },
      {
        credentialSubject: {
          id: 'https://student2.example/profile',
          name: 'Student Two'
        }
      }
    ];

    const credentials = await issuer.batchIssueCredentials(credentialRequests);
    
    expect(credentials).toHaveLength(2);
    expect(credentials[0].credentialSubject).toEqual({
      id: 'https://student1.example/profile',
      name: 'Student One'
    });
    expect(credentials[1].credentialSubject).toEqual({
      id: 'https://student2.example/profile',
      name: 'Student Two'
    });
  });

  test('should update issuer information', () => {
    issuer.updateIssuerInfo({
      name: 'Updated University Name',
      description: 'Updated description'
    });

    const updatedInfo = issuer.getIssuerInfo();
    expect(updatedInfo.name).toBe('Updated University Name');
    expect(updatedInfo.description).toBe('Updated description');
    expect(updatedInfo.id).toBe('https://university.edu'); // Should remain unchanged
  });
});
