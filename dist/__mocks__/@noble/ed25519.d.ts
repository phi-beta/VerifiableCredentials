/**
 * Mock for @noble/ed25519 for testing
 */
export declare const sign: (data: Uint8Array, privateKey: Uint8Array) => Promise<Uint8Array>;
export declare const verify: (signature: Uint8Array, data: Uint8Array, publicKey: Uint8Array) => Promise<boolean>;
export declare const getPublicKey: (privateKey: Uint8Array) => Uint8Array;
export declare const utils: {
    randomPrivateKey: () => Uint8Array;
};
//# sourceMappingURL=ed25519.d.ts.map