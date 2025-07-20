// generate-headers.js
// Final corrected script separating real and pseudo-headers.

import { DateTime } from 'luxon';
import { URL } from 'url';
import ebaySignature from 'digital-signature-nodejs-sdk';

// --- Step 1: PASTE YOUR KEYS HERE ---
const JWE = "eyJ6aXAiOiJERUYiLCJraWQiOiJhZjE4NDE3NC0wMjg2LTQ2OWQtOWJhZi04MmM3NWFmZDIwZDUiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiOTRBME0xUHZhb0JNbDZJSFgyWkh2USIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiX1JRV3l6S3p2bzhwQlg4ZiJ9.nP2qTvySNH5A35P3fvJTYiSJki9Vngfikr9KS34yDWE.9RD2ry-8yCEBWhiP.Ey3jh_aMNnHl8sR2NP4r-IFA4fISC2s92eS63SsVm2OLepIgwUMkSpDLUGp6xKTtwbYwRWWcqiacWcsCL0ZFWGSkX7wEUriV8gzIvievfRFagbXY_0DU1bmLX-rSzPxGFFTFi6p6F-38BVa90JX8xvCKmsaK6VMogwK6YqLcNlEqGSOOfNRg9TZJoG8-aR0uXZuoJyL66ECAVVYZwaR4eq6SI0O-F5bmDImzDrcPwonhgfPR1gyz4YJADCzKYFrMTcQ1d6nUxU2PtkY.7RQSwFc13X_BChZpwuPMvA";
const PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEIAXSxEITj2ad0jOQMmZR2ETx/qAL46VJhRysVF9xYBai";

// --- Main execution logic ---
try {
    if (JWE === "YOUR_JWE_HERE" || PRIVATE_KEY === "YOUR_PRIVATE_KEY_HERE") {
        throw new Error("Please replace the placeholder JWE and PRIVATE_KEY values in the script.");
    }

    console.log("--- Starting Header Generation ---");

    // 1. Generate the dynamic URL
    const baseUrl = 'https://api.ebay.com/sell/finances/v1/transaction';
    const startDate = DateTime.now().setZone('utc').minus({ weeks: 1 }).toISO();
    const endDate = DateTime.now().setZone('utc').toISO();
    const filterValue = `transactionDate:[${startDate}..${endDate}]`;
    const typeValue = '{SALE,REFUND}';
    const finalUrl = `${baseUrl}?filter=${encodeURIComponent(filterValue)}&transactionType=${encodeURIComponent(typeValue)}`;
    const parsedUrl = new URL(finalUrl);
    
    console.log(`[INFO] Using URL: ${finalUrl}`);

    // 2. Create the configuration object
    const config = {
        privateKey: `-----BEGIN PRIVATE KEY-----\n${PRIVATE_KEY}\n-----END PRIVATE KEY-----`,
        signatureParams: [
            'x-ebay-signature-key',
            '@method',
            '@path',
            '@authority'
        ],
        // THIS OBJECT NOW ONLY CONTAINS PSEUDO-HEADERS
        signatureComponents: {
            '@method': 'GET',
            '@path': parsedUrl.pathname + parsedUrl.search,
            '@authority': parsedUrl.host
        }
    };

    // 3. Create a separate object for REAL HTTP headers to be signed
    const headersToSign = {
        'x-ebay-signature-key': JWE
    };

    // 4. Generate the signature, passing real headers as the first argument
    const signatureInput = ebaySignature.generateSignatureInput(headersToSign, config);
    const signature = ebaySignature.generateSignature(headersToSign, config);
    
    // 5. Assemble and print the final headers
    const finalHeaders = {
        'x-ebay-signature-key': JWE,
        'Signature-Input': signatureInput,
        'Signature': signature,
        'URL-to-call': finalUrl
    };

    console.log("\n✅ --- SUCCESS: Generated Headers --- ✅");
    console.log(JSON.stringify(finalHeaders, null, 2));
    console.log("\n");

} catch (error) {
    console.error('\n❌ --- SCRIPT FAILED --- ❌');
    console.error(error.message);
    console.error(error.stack);
}