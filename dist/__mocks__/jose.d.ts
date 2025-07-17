/**
 * Mock for jose library for testing
 */
export declare class SignJWT {
    private payload;
    constructor(payload: any);
    setProtectedHeader(header: any): this;
    setIssuedAt(): this;
    setExpirationTime(exp: string): this;
    sign(key: any): Promise<string>;
}
export declare const jwtVerify: (jwt: string, key: any) => Promise<{
    payload: any;
}>;
export declare const importJWK: (jwk: any) => Promise<any>;
export declare const exportJWK: (key: any) => Promise<any>;
export declare const generateKeyPair: (alg: string) => Promise<{
    publicKey: any;
    privateKey: any;
}>;
//# sourceMappingURL=jose.d.ts.map