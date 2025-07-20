// sign-server.js - Final version implementing the non-standard path signing.

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { DateTime } from 'luxon';
import { URL } from 'url';
import ebaySignature from 'digital-signature-nodejs-sdk';

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

app.post('/sign-sdk', (req, res) => {
    try {
        console.log("\n--- New SDK Signing Request Received ---");
        const { keys } = req.body;
        if (!keys || !keys.jwe || !keys.privatekey) {
            throw new Error("Request must include JWE and Private Key.");
        }

        const JWE = keys.jwe;
        const PRIVATE_KEY = keys.privatekey;

        // 1. Generate the FULL URL with query parameters. This will be sent to n8n for the final API call.
        const baseUrl = 'https://api.ebay.com/sell/finances/v1/transaction';
        const startDate = DateTime.now().setZone('utc').minus({ weeks: 1 }).toISO();
        const endDate = DateTime.now().setZone('utc').toISO();
        const filterValue = `transactionDate:[${startDate}..${endDate}]`;
        const typeValue = '{SALE,REFUND}';
        const finalUrl = `${baseUrl}?filter=${encodeURIComponent(filterValue)}&transactionType=${encodeURIComponent(typeValue)}`;
        const parsedUrl = new URL(finalUrl);
        
        console.log(`[INFO] Full URL for API call: ${finalUrl}`);

        // 2. Create the configuration for the SDK.
        const config = {
            privateKey: `-----BEGIN PRIVATE KEY-----\n${PRIVATE_KEY}\n-----END PRIVATE KEY-----`,
            signatureParams: ['x-ebay-signature-key', '@method', '@path', '@authority'],
            signatureComponents: {
                '@method': 'GET',
                // --- THE CRITICAL FIX IS HERE ---
                // Per community findings, we sign ONLY the pathname, ignoring the query string.
                '@path': parsedUrl.pathname,
                '@authority': parsedUrl.host
            }
        };

        // 3. Generate the signature using the base path.
        const headersToSign = { 'x-ebay-signature-key': JWE };
        const signatureInput = ebaySignature.generateSignatureInput(headersToSign, config);
        const signature = ebaySignature.generateSignature(headersToSign, config);
        
        // 4. Send the response back to n8n. It contains the signature (based on the short path)
        // and the FULL URL for n8n to call.
        const finalResponse = {
            'x-ebay-signature-key': JWE,
            'Signature-Input': signatureInput,
            'Signature': signature,
            'url': finalUrl 
        };

        console.log("✅ --- SUCCESS: Signature Generated --- ✅");
        res.status(200).json(finalResponse);

    } catch (error) {
        console.error('\n❌ --- SCRIPT FAILED --- ❌');
        console.error(error.stack);
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`✅ Final Signing Server listening on port ${port}`);
});