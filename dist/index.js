"use strict";
/**
 * W3C Verifiable Credentials TypeScript Implementation
 * Main entry point for the library
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.VERSION = exports.OIDC4VCClient = exports.OIDC4VPServer = exports.OIDC4VCIServer = exports.schemaValidator = exports.SchemaValidator = exports.ValidationEngine = exports.Verifier = exports.Holder = exports.Issuer = void 0;
// Core types and interfaces
__exportStar(require("./types"), exports);
// JSON-LD Context management
__exportStar(require("./context"), exports);
// Security and cryptographic operations
__exportStar(require("./security"), exports);
// Role implementations
var issuer_1 = require("./roles/issuer");
Object.defineProperty(exports, "Issuer", { enumerable: true, get: function () { return issuer_1.Issuer; } });
var holder_1 = require("./roles/holder");
Object.defineProperty(exports, "Holder", { enumerable: true, get: function () { return holder_1.Holder; } });
var verifier_1 = require("./roles/verifier");
Object.defineProperty(exports, "Verifier", { enumerable: true, get: function () { return verifier_1.Verifier; } });
// Validation engine
var validation_1 = require("./validation");
Object.defineProperty(exports, "ValidationEngine", { enumerable: true, get: function () { return validation_1.ValidationEngine; } });
// Schema validation
var schema_1 = require("./schema");
Object.defineProperty(exports, "SchemaValidator", { enumerable: true, get: function () { return schema_1.SchemaValidator; } });
Object.defineProperty(exports, "schemaValidator", { enumerable: true, get: function () { return schema_1.schemaValidator; } });
// Utility functions
__exportStar(require("./utils"), exports);
// OIDC4VC (OpenID Connect for Verifiable Credentials)
var oidc4vc_1 = require("./oidc4vc");
Object.defineProperty(exports, "OIDC4VCIServer", { enumerable: true, get: function () { return oidc4vc_1.OIDC4VCIServer; } });
Object.defineProperty(exports, "OIDC4VPServer", { enumerable: true, get: function () { return oidc4vc_1.OIDC4VPServer; } });
Object.defineProperty(exports, "OIDC4VCClient", { enumerable: true, get: function () { return oidc4vc_1.OIDC4VCClient; } });
// Version information
exports.VERSION = '1.0.0';
//# sourceMappingURL=index.js.map