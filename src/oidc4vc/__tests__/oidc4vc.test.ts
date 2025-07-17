/**
 * Tests for OIDC4VC functionality
 */

import { 
  OIDC4VCIServer, 
  OIDC4VPServer, 
  OIDC4VCClient,
  type OIDC4VCIConfig,
  type OIDC4VPConfig 
} from '../index';
import { Issuer } from '../../roles/issuer';
import { Holder } from '../../roles/holder';
import { Verifier } from '../../roles/verifier';

describe('OIDC4VC', () => {
  let issuer: Issuer;
  let holder: Holder;
  let verifier: Verifier;

  beforeEach(async () => {
    issuer = new Issuer({
      id: 'https://test-university.edu',
      name: 'Test University'
    });

    // Generate key pair for issuer
    const issuerSecurityManager = (issuer as any).securityManager;
    await issuerSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');

    holder = new Holder({
      id: 'https://test-student.example',
      name: 'Test Student'
    });

    // Generate key pair for holder
    const holderSecurityManager = (holder as any).securityManager;
    await holderSecurityManager.generateKeyPair('Ed25519', 'placeholder-key');

    verifier = new Verifier({
      id: 'https://test-verifier.com',
      name: 'Test Verifier',
      trustedIssuers: ['https://test-university.edu']
    });
  });

  describe('OIDC4VCIServer', () => {
    test('should create server with correct configuration', () => {
      const config: OIDC4VCIConfig = {
        issuerUrl: 'http://localhost:3001',
        port: 3001,
        supportedCredentialTypes: ['TestCredential'],
        issuer
      };

      const server = new OIDC4VCIServer(config);
      expect(server).toBeInstanceOf(OIDC4VCIServer);
    });

    test('should track issued credentials', async () => {
      const config: OIDC4VCIConfig = {
        issuerUrl: 'http://localhost:3001',
        port: 3001,
        supportedCredentialTypes: ['TestCredential'],
        issuer
      };

      const server = new OIDC4VCIServer(config);
      const initialCredentials = server.getIssuedCredentials();
      expect(initialCredentials).toHaveLength(0);
    });
  });

  describe('OIDC4VPServer', () => {
    test('should create server with correct configuration', () => {
      const config: OIDC4VPConfig = {
        verifierUrl: 'http://localhost:3002',
        port: 3002,
        verifier,
        clientId: 'test-client',
        redirectUri: 'http://localhost:3002/callback'
      };

      const server = new OIDC4VPServer(config);
      expect(server).toBeInstanceOf(OIDC4VPServer);
    });

    test('should track verification results', () => {
      const config: OIDC4VPConfig = {
        verifierUrl: 'http://localhost:3002',
        port: 3002,
        verifier,
        clientId: 'test-client',
        redirectUri: 'http://localhost:3002/callback'
      };

      const server = new OIDC4VPServer(config);
      const results = server.getVerificationResults();
      expect(results).toBeInstanceOf(Map);
      expect(results.size).toBe(0);
    });
  });

  describe('OIDC4VCClient', () => {
    test('should create client with holder', () => {
      const client = new OIDC4VCClient(holder);
      expect(client).toBeInstanceOf(OIDC4VCClient);
    });

    test('should handle credential offer acceptance gracefully', async () => {
      const client = new OIDC4VCClient(holder);
      
      // Test with invalid URL - should throw error
      await expect(client.acceptCredentialOffer('invalid-url')).rejects.toThrow();
    });

    test('should handle presentation submission gracefully', async () => {
      const client = new OIDC4VCClient(holder);
      
      // Test with invalid URL - should throw error
      await expect(client.submitPresentation('invalid-url', ['TestCredential'])).rejects.toThrow();
    });
  });

  describe('Integration', () => {
    test('should support full OIDC4VC workflow concept', async () => {
      // Create server configurations
      const vciConfig: OIDC4VCIConfig = {
        issuerUrl: 'http://localhost:3001',
        port: 3001,
        supportedCredentialTypes: ['TestCredential'],
        issuer
      };

      const vpConfig: OIDC4VPConfig = {
        verifierUrl: 'http://localhost:3002',
        port: 3002,
        verifier,
        clientId: 'test-client',
        redirectUri: 'http://localhost:3002/callback'
      };

      // Create servers (don't start them to avoid port conflicts in tests)
      const vciServer = new OIDC4VCIServer(vciConfig);
      const vpServer = new OIDC4VPServer(vpConfig);
      const client = new OIDC4VCClient(holder);

      // Verify server creation
      expect(vciServer).toBeInstanceOf(OIDC4VCIServer);
      expect(vpServer).toBeInstanceOf(OIDC4VPServer);
      expect(client).toBeInstanceOf(OIDC4VCClient);

      // Verify initial state
      expect(vciServer.getIssuedCredentials()).toHaveLength(0);
      expect(vpServer.getVerificationResults().size).toBe(0);
    });
  });
});
