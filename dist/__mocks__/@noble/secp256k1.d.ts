/**
 * Mock for @noble/secp256k1 for testing
 */
export declare const sign: (data: Uint8Array, privateKey: Uint8Array) => Uint8Array;
export declare const verify: (signature: Uint8Array, data: Uint8Array, publicKey: Uint8Array) => boolean;
export declare const getPublicKey: (privateKey: Uint8Array) => Uint8Array;
export declare const utils: {
    randomPrivateKey: () => Uint8Array;
};
//# sourceMappingURL=secp256k1.d.ts.map