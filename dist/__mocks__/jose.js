"use strict";
/**
 * Mock for jose library for testing
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = exports.exportJWK = exports.importJWK = exports.jwtVerify = exports.SignJWT = void 0;
class SignJWT {
    constructor(payload) {
        this.payload = payload;
    }
    setProtectedHeader(header) {
        return this;
    }
    setIssuedAt() {
        return this;
    }
    setExpirationTime(exp) {
        return this;
    }
    async sign(key) {
        // Mock JWT token
        return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    }
}
exports.SignJWT = SignJWT;
const jwtVerify = async (jwt, key) => {
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
exports.jwtVerify = jwtVerify;
const importJWK = async (jwk) => {
    return {};
};
exports.importJWK = importJWK;
const exportJWK = async (key) => {
    return {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'mock-public-key',
        d: 'mock-private-key'
    };
};
exports.exportJWK = exportJWK;
const generateKeyPair = async (alg) => {
    return {
        publicKey: {},
        privateKey: {}
    };
};
exports.generateKeyPair = generateKeyPair;
//# sourceMappingURL=jose.js.map