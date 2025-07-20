import crypto from 'crypto';
import fetch from 'node-fetch';
import { URL } from 'url';

// --- 1. PASTE YOUR RENDER VERIFIER URL HERE ---
const VERIFIER_URL = 'https://ebay-verifier.onrender.com/verifysignature';

// --- Static test data from the eBay README ---
const testBodyString = '{"hello": "world"}';
const testJWE = "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiSXh2dVRMb0FLS0hlS0Zoa3BxQ05CUSIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiaFd3YjNoczk2QzEyOTNucCJ9.2o02pR9SoTF4g_5qRXZm6tF4H52TarilIAKxoVUqjd8.3qaF0KJN-rFHHm_P.AMUAe9PPduew09mANIZ-O_68CCuv6EIx096rm9WyLZnYz5N1WFDQ3jP0RBkbaOtQZHImMSPXIHVaB96RWshLuJsUgCKmTAwkPVCZv3zhLxZVxMXtPUuJ-ppVmPIv0NzznWCOU5Kvb9Xux7ZtnlvLXgwOFEix-BaWNomUAazbsrUCbrp514GIea3butbyxXLNi6R9TJUNh8V2uan-optT1MMyS7eMQnVGL5rYBULk.9K5ucUqAu0DqkkhgubsHHw";
const testPrivateKeyB64 = "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF";

async function runManualTest() {
    try {
        console.log("--- 1. Generating Signature Manually ---");

        // Step 1: Create the Content-Digest
        const digest = `sha-256=:${crypto.createHash('sha256').update(testBodyString).digest('base64')}:`;

        // Step 2: Manually create the Signature-Input header with a current timestamp
        const created = Math.floor(Date.now() / 1000);
        const signatureInput = `sig1=("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created=${created}`;

        // Step 3: Manually build the exact signature base string
        const parsedUrl = new URL(VERIFIER_URL);
        const signatureParamsValue = signatureInput.substring(5); // Remove 'sig1='
        
        const signatureBaseLines = [
            `"content-digest": ${digest}`,
            `"x-ebay-signature-key": ${testJWE}`,
            `"@method": POST`,
            `"@path": ${parsedUrl.pathname}`,
            `"@authority": ${parsedUrl.host}`,
            `"@signature-params": ${signatureParamsValue}`
        ];
        const signatureBase = signatureBaseLines.join('\n');
        console.log("\nManually constructed Signature Base:\n---\n" + signatureBase + "\n---");

        // Step 4: Sign the base string using Node.js crypto
        const privateKey = crypto.createPrivateKey({
            key: `-----BEGIN PRIVATE KEY-----\n${testPrivateKeyB64}\n-----END PRIVATE KEY-----`,
            format: 'pem'
        });
        const signatureBytes = crypto.sign(null, Buffer.from(signatureBase), privateKey);
        
        // Step 5: Format the final Signature header
        const signature = `sig1=:${signatureBytes.toString('base64')}:`;
        
        const requestHeaders = {
            'Content-Type': 'application/json',
            'Content-Digest': digest,
            'x-ebay-signature-key': testJWE,
            'Signature-Input': signatureInput,
            'Signature': signature
        };

        console.log("✅ --- HEADERS GENERATED MANUALLY --- ✅");

        // Step 6: Send for verification
        console.log(`\n--- 2. Sending request to ${VERIFIER_URL} ---`);

        const response = await fetch(VERIFIER_URL, {
            method: 'POST',
            headers: requestHeaders,
            body: testBodyString
        });

        const responseBody = await response.text();

        if (response.ok) {
            console.log("\n✅ --- VERIFICATION SUCCESS! --- ✅");
            console.log(`Status: ${response.status} ${response.statusText}`);
        } else {
            console.error("\n❌ --- VERIFICATION FAILED --- ❌");
            console.error(`Status: ${response.status}`);
            console.error(`Response: ${responseBody}`);
        }

    } catch (error) {
        console.error('\n❌ --- SCRIPT FAILED --- ❌', error);
    }
}

runManualTest();