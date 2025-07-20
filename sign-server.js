// server.js - Final version with manual crypto implementation

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import crypto from 'crypto';
import { URL } from 'url';

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// A single, robust endpoint to generate signatures
app.post('/sign', (req, res) => {
    try {
        const { keys, url } = req.body;
        if (!keys || !keys.jwe || !keys.privatekey || !url) {
            throw new Error("Request body must include 'url' and a 'keys' object.");
        }

        const JWE = keys.jwe;
        const PRIVATE_KEY = keys.privatekey;
        const finalUrl = url;
        const parsedUrl = new URL(finalUrl);

        // Step 1: Manually create the Signature-Input header
        const created = Math.floor(Date.now() / 1000);
        const signatureInput = `sig1=("x-ebay-signature-key" "@method" "@path" "@authority");created=${created}`;

        // Step 2: Manually build the exact signature base string
        const signatureParamsValue = signatureInput.substring(5); // Remove 'sig1='
        const signatureBaseLines = [
            `"x-ebay-signature-key": ${JWE}`,
            `"@method": GET`,
            `"@path": ${parsedUrl.pathname}`, // Using the non-standard rule of base path only
            `"@authority": ${parsedUrl.host}`,
            `"@signature-params": ${signatureParamsValue}`
        ];
        const signatureBase = signatureBaseLines.join('\n');

        // Step 3: Sign the base string using Node.js crypto
        const privateKeyPEM = crypto.createPrivateKey({
            key: `-----BEGIN PRIVATE KEY-----\n${PRIVATE_KEY}\n-----END PRIVATE KEY-----`,
            format: 'pem'
        });
        const signatureBytes = crypto.sign(null, Buffer.from(signatureBase), privateKeyPEM);
        
        // Step 4: Format the final Signature header
        const signature = `sig1=:${signatureBytes.toString('base64')}:`;
        
        // Step 5: Assemble the final response for n8n
        const finalResponse = {
            'x-ebay-signature-key': JWE,
            'Signature-Input': signatureInput,
            'Signature': signature,
            'url': finalUrl 
        };
        
        res.status(200).json(finalResponse);

    } catch (error) {
        console.error(error.stack);
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`✅ Final Manual Signing Server listening on port ${port}`);
});