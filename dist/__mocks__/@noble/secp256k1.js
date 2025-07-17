"use strict";
/**
 * Mock for @noble/secp256k1 for testing
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.getPublicKey = exports.verify = exports.sign = void 0;
const sign = (data, privateKey) => {
    // Mock signature - just return a fixed 64-byte signature
    return new Uint8Array(64).fill(1);
};
exports.sign = sign;
const verify = (signature, data, publicKey) => {
    // Mock verification - always return true for valid structure
    return signature.length === 64 && data.length > 0 && publicKey.length === 33;
};
exports.verify = verify;
const getPublicKey = (privateKey) => {
    // Mock public key derivation
    return new Uint8Array(33).fill(2);
};
exports.getPublicKey = getPublicKey;
exports.utils = {
    randomPrivateKey: () => {
        return new Uint8Array(32).fill(3);
    }
};
//# sourceMappingURL=secp256k1.js.map