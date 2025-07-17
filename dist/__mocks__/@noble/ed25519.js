"use strict";
/**
 * Mock for @noble/ed25519 for testing
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.getPublicKey = exports.verify = exports.sign = void 0;
const sign = async (data, privateKey) => {
    // Mock signature - just return a fixed 64-byte signature
    return new Uint8Array(64).fill(1);
};
exports.sign = sign;
const verify = async (signature, data, publicKey) => {
    // Mock verification - always return true for valid structure
    return signature.length === 64 && data.length > 0 && publicKey.length === 32;
};
exports.verify = verify;
const getPublicKey = (privateKey) => {
    // Mock public key derivation
    return new Uint8Array(32).fill(2);
};
exports.getPublicKey = getPublicKey;
exports.utils = {
    randomPrivateKey: () => {
        return new Uint8Array(32).fill(3);
    }
};
//# sourceMappingURL=ed25519.js.map