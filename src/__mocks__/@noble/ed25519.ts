/**
 * Mock for @noble/ed25519 for testing
 */

export const sign = async (data: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> => {
  // Mock signature - just return a fixed 64-byte signature
  return new Uint8Array(64).fill(1);
};

export const verify = async (signature: Uint8Array, data: Uint8Array, publicKey: Uint8Array): Promise<boolean> => {
  // Mock verification - always return true for valid structure
  return signature.length === 64 && data.length > 0 && publicKey.length === 32;
};

export const getPublicKey = (privateKey: Uint8Array): Uint8Array => {
  // Mock public key derivation
  return new Uint8Array(32).fill(2);
};

export const utils = {
  randomPrivateKey: (): Uint8Array => {
    return new Uint8Array(32).fill(3);
  }
};
