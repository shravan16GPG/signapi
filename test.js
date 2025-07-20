// test-sign.js - Local testing of eBay Digital Signature SDK with static credentials

import ntpClient from 'ntp-client';
// No need for 'url' module in this test file unless you're explicitly parsing URLs
// import { URL } from 'url';

// --- CORRECTED IMPORT STATEMENT ---
// Import all exports under a namespace, as shown in the SDK's own examples.
import * as DigitalSignatureSDK from 'digital-signature-nodejs-sdk';
const { ClientSigner, KeyInfo } = DigitalSignatureSDK; // Destructure the classes from the imported namespace
// --- END CORRECTED IMPORT ---

// --- STATIC CREDENTIALS (REPLACE WITH YOUR ACTUAL TEST KEYS) ---
// IMPORTANT: Replace these with valid JWE and raw private key strings from your eBay Key Management API.
// The JWE should be the full string from the 'jwe' field.
// The private key should be the raw string from the 'privateKey' field.
const STATIC_JWE = `eyJhbGciOiJBMjU2Q0JDIiwiY2t5IjoicXgxdDJoMzUzZTRnNXM2djd3OHk5eiIsImVuYyI6IkEyNTZHQ00iLCJpYXQiOjE2NzgyNjIyMjgsImlzcyI6ImFwaS5lYmF5LmNvbS9rZXlfbWFuYWdlbWVudC92MS9zaWduaW5nX2tleSIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFTDI1NTE5IiwidXNlIjoic2lnIiwieCI6IlJ1eml5a1FqMjUzZ0hHbzJ6c0xwd0QyX19zM09oY2g1WnB3LVA0S00yYk81YjVhYkR4c3Z4czB5cWJkdW1wV2Z5aE4ybiJ9LCJraWQiOiJmOGIwOGYyMC02YjcwLTRlMDMtYmMzMi0wM2Y4NTFjZTUxNzEiLCJwcm90ZWN0ZWQiOlsiYWxnIiwic2lnIl19.eyJleHAiOjE3MDk4MTk4MjgsImlhdCI6MTY3ODI2MjIyOCwia2lkIjoiZjhiMDhmMjAtNmI3MC00ZTAzLWJjMzItMDNmODUxY2U1MTcxIn0.YOUR_ACTUAL_JWE_GOES_HERE.YOUR_ACTUAL_ENCRYPTED_KEY_GOES_HERE`;
const STATIC_PRIVATE_KEY = `MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=`;

// --- TEST REQUEST PARAMETERS ---
const TEST_METHOD = 'GET';
const TEST_URL = 'https://api.ebay.com/sell/finances/v1/transaction?filter=transactionDate:[2024-07-01T00:00:00.000Z..2024-07-01T23:59:59.999Z]&transactionType={SALE,REFUND}';
const TEST_BODY = null; // Important: for GET requests, body should be null

async function testDigitalSignature() {
    let date;
    try {
        date = await new Promise((resolve, reject) => {
            // Using a more robust NTP client call with timeout
            ntpClient.getNetworkTime("a.st1.ntp.br", 123, (err, ntpDate) => {
                if (err) {
                    console.warn("⚠️ NTP Error (using system time as fallback):", err.message);
                    resolve(new Date()); // Fallback to system time
                } else {
                    console.log(`⏰ NTP Time obtained: ${ntpDate.toISOString()}`);
                    resolve(ntpDate);
                }
            });
        });
    } catch (error) {
        console.error("💥 Error fetching NTP time:", error.message);
        date = new Date(); // Fallback in case of promise rejection
    }

    try {
        console.log("\n--- Starting Digital Signature Test ---");
        console.log("🛠️ Using Static JWE (partial):", STATIC_JWE.substring(0, 50) + "...");
        console.log("🛠️ Using Static Private Key (partial):", STATIC_PRIVATE_KEY.substring(0, 50) + "...");
        console.log("📥 Test Method:", TEST_METHOD);
        console.log("🔗 Test URL:", TEST_URL);
        console.log("📦 Test Body:", TEST_BODY === null ? "null (GET request)" : JSON.stringify(TEST_BODY, null, 2));

        // Create KeyInfo object
        const keyInfo = new KeyInfo(STATIC_JWE, STATIC_PRIVATE_KEY);
        const signer = new ClientSigner(keyInfo);

        // Prepare the request object for the SDK
        const requestToSign = {
            method: TEST_METHOD.toUpperCase(),
            url: TEST_URL,
            headers: {
                'Content-Type': 'application/json' // Assuming your API call would send this
            },
            body: TEST_BODY !== null ? JSON.stringify(TEST_BODY) : undefined // SDK expects undefined for no body
        };

        console.log("\n--- Object Passed to eBay Digital Signature SDK ---");
        console.log("📜 SDK Input Method:", requestToSign.method);
        console.log("🌐 SDK Input URL:", requestToSign.url);
        console.log("✉️ SDK Input Body:", requestToSign.body || "null/undefined (no Content-Digest will be generated)");
        console.log("--- End SDK Input Log ---\n");

        // Use the SDK to sign the request
        const signedHeaders = await signer.sign(requestToSign, date.getTime());

        console.log(`✅ Successfully signed request.`);
        console.log(`⏱️ Timestamp used for Signature-Input (NTP time ms): ${date.getTime()}`);
        console.log("📝 **Generated Signed Headers (to send to eBay):**");
        console.log(JSON.stringify(signedHeaders, null, 2));
        console.log("--- End Digital Signature Test ---\n");

    } catch (error) {
        console.error('❌ Error during signing process:', error.message);
        console.error('Stack:', error.stack);
    }
}

// Run the test function
testDigitalSignature();