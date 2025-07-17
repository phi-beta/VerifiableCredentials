/**
 * Mock for jose library for testing
 */

export class SignJWT {
  private payload: any;

  constructor(payload: any) {
    this.payload = payload;
  }

  setProtectedHeader(header: any): this {
    return this;
  }

  setIssuedAt(): this {
    return this;
  }

  setExpirationTime(exp: string): this {
    return this;
  }

  async sign(key: any): Promise<string> {
    // Mock JWT token
    return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  }
}

export const jwtVerify = async (jwt: string, key: any): Promise<{ payload: any }> => {
  // Mock JWT verification
  return {
    payload: {
      vc: {},
      iss: 'did:example:issuer',
      aud: 'https://example.com',
      iat: Math.floor(Date.now() / 1000)
    }
  };
};

export const importJWK = async (jwk: any): Promise<any> => {
  return {};
};

export const exportJWK = async (key: any): Promise<any> => {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'mock-public-key',
    d: 'mock-private-key'
  };
};

export const generateKeyPair = async (alg: string): Promise<{ publicKey: any; privateKey: any }> => {
  return {
    publicKey: {},
    privateKey: {}
  };
};
