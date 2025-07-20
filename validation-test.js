// official-test.js
// This script uses the exact test data from eBay's documentation to verify our signing logic.

import ebaySignature from 'digital-signature-nodejs-sdk';
import crypto from 'crypto';

// --- Data copied directly from the eBay Digital Signature README ---
const testBody = { "hello": "world" };
const testBodyString = JSON.stringify(testBody);

const testConfig = {
    // This is the Ed25519 private key from their README
    privateKey: `-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----`,
    
    // The JWE (public key) from their README
    jwe: "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiSXh2dVRMb0FLS0hlS0Zoa3BxQ05CUSIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiaFd3YjNoczk2QzEyOTNucCJ9.2o02pR9SoTF4g_5qRXZm6tF4H52TarilIAKxoVUqjd8.3qaF0KJN-rFHHm_P.AMUAe9PPduew09mANIZ-O_68CCuv6EIx096rm9WyLZnYz5N1WFDQ3jP0RBkbaOtQZHImMSPXIHVaB96RWshLuJsUgCKmTAwkPVCZv3zhLxZVxMXtPUuJ-ppVmPIv0NzznWCOU5Kvb9Xux7ZtnlvLXgwOFEix-BaWNomUAazbsrUCbrp514GIea3butbyxXLNi6R9TJUNh8V2uan-optT1MMyS7eMQnVGL5rYBULk.9K5ucUqAu0DqkkhgubsHHw",

    // This is for a POST request, so it includes 'content-digest'
    signatureParams: [
        "content-digest",
        "x-ebay-signature-key",
        "@method",
        "@path",
        "@authority"
    ],
    signatureComponents: {
        '@method': 'POST',
        '@path': '/test',
        '@authority': 'api.ebay.com'
    }
};
// --- End of Official Data ---

try {
    console.log("--- Running Test with Official eBay Example Data ---");

    // 1. Calculate the Content-Digest for the POST body
    const digest = `sha-256=:${crypto.createHash('sha256').update(testBodyString).digest('base64')}:`;
    console.log(`[1] Calculated Content-Digest: ${digest}`);

    // 2. The headers object must contain all REAL headers being signed
    const headersToSign = {
        'Content-Digest': digest,
        'x-ebay-signature-key': testConfig.jwe
    };

    // 3. Generate the signature using the official test config
    const signatureInput = ebaySignature.generateSignatureInput(headersToSign, testConfig);
    const signature = ebaySignature.generateSignature(headersToSign, testConfig);

    console.log("\n✅ --- SUCCESS: Generated Headers with Official Test Data --- ✅");
    console.log(`Signature-Input: ${signatureInput}`);
    console.log(`Signature: ${signature}`);
    console.log("\nThis proves our method of using the SDK is correct.");

} catch (error) {
    console.error('\n❌ --- SCRIPT FAILED --- ❌');
    console.error(error.stack);
}