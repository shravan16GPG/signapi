// sign-server.js - Final version that accepts a URL in the request body

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
        // Now accepts 'keys' and 'url' from the request body
        const { keys, url } = req.body;
        if (!keys || !keys.jwe || !keys.privatekey || !url) {
            throw new Error("Request body must include 'url' and a 'keys' object with 'jwe' and 'privatekey'.");
        }

        const JWE = keys.jwe;
        const PRIVATE_KEY = keys.privatekey;
        
        // The URL is now taken directly from the request
        const finalUrl = url;
        const parsedUrl = new URL(finalUrl);
        
        console.log(`[INFO] Signing URL: ${finalUrl}`);

        const config = {
            privateKey: `-----BEGIN PRIVATE KEY-----\n${PRIVATE_KEY}\n-----END PRIVATE KEY-----`,
            signatureParams: ['x-ebay-signature-key', '@method', '@path', '@authority'],
            signatureComponents: {
                '@method': 'GET',
                '@path': parsedUrl.pathname, // Sign only the base path
                '@authority': parsedUrl.host
            }
        };

        const headersToSign = { 'x-ebay-signature-key': JWE };
        const signatureInput = ebaySignature.generateSignatureInput(headersToSign, config);
        const signature = ebaySignature.generateSignature(headersToSign, config);
        
        const finalResponse = {
            'x-ebay-signature-key': JWE,
            'Signature-Input': signatureInput,
            'Signature': signature,
            'url': finalUrl 
        };
        
        console.log("✅ --- SUCCESS: Signature Generated --- ✅");
        res.status(200).json(finalResponse);

    } catch (error) {
        console.error(error.stack);
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`✅ Final Generic Signing Server listening on port ${port}`);
});