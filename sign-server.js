// sign-server.js (FINAL VERSION with SEC1 Key Fix)

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import base64url from 'base64url';
import crypto from 'crypto';
import { URL } from 'url';
import ntpClient from 'ntp-client';
import { DateTime } from 'luxon';
import ebaySignature from 'digital-signature-nodejs-sdk';



const app = express();
const port = process.env.PORT || 3000;

// --- Middleware Setup ---
app.use(cors());
app.use(bodyParser.json());


// --- Utility Functions ---
function sha256Digest(payload) {
  const hash = crypto.createHash('sha256');
  hash.update(payload, 'utf8');
  return `sha-256=:${hash.digest('base64')}:`;
}

function formatPrivateKeyToPEM(rawKey) {
  return `-----BEGIN PRIVATE KEY-----\n${rawKey}\n-----END PRIVATE KEY-----`;
}

// THIS FUNCTION IS NOW CORRECTED
function signEd25519(base, privateKeyPem) {
  try {
    const key = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: 'sec1' // <-- THIS IS THE FIX (changed from 'pkcs8')
    });
    const sign = crypto.sign(null, Buffer.from(base, 'utf8'), key);
    return base64url.encode(sign);
  } catch (e) {
    console.error("Error creating private key. Check if the key format is correct.", e);
    throw e;
  }
}


// --- Signer Endpoint ---
app.post('/sign', (req, res) => {
  ntpClient.getNetworkTime("a.st1.ntp.br", 123, (err, date) => {
    if (err) {
      console.error("NTP Error:", err);
      date = new Date();
    }

    try {
      const { method, url, keys, body } = req.body;
      if (!method || !url || !keys || !keys.jwe || !keys.privatekey) {
        return res.status(400).json({
          error: "Request body must include 'method', 'url', and a 'keys' object with 'jwe' and 'privatekey'."
        });
      }

      const created = Math.floor(date.getTime() / 1000);
      const parsedUrl = new URL(url);
      const methodUpper = method.toUpperCase();
      const responseHeaders = { 'x-ebay-signature-key': keys.jwe };
      let digest = null;
      let coveredComponents = ['"x-ebay-signature-key"', '"@method"', '"@path"', '"@authority"'];

      if (["POST", "PUT", "PATCH"].includes(methodUpper)) {
        const payload = body ? JSON.stringify(body) : '{}';
        digest = sha256Digest(payload);
        responseHeaders['Content-Digest'] = digest;
        coveredComponents.unshift('"content-digest"');
      }

      const signatureInputString = `sig1=(${coveredComponents.join(' ')});created=${created}`;
      const signatureBaseLines = [];
      if (digest) { signatureBaseLines.push(`"content-digest": ${digest}`); }
      signatureBaseLines.push(`"x-ebay-signature-key": ${keys.jwe}`);
      signatureBaseLines.push(`"@method": ${methodUpper}`);
      const pathWithQuery = parsedUrl.pathname + parsedUrl.search;
      signatureBaseLines.push(`"@path": ${pathWithQuery}`);
      signatureBaseLines.push(`"@authority": ${parsedUrl.host}`);
      signatureBaseLines.push(`"@signature-params": ${signatureInputString}`);
      const signatureBase = signatureBaseLines.join('\n');
      const privateKeyPEM = formatPrivateKeyToPEM(keys.privatekey);
      const signature = signEd25519(signatureBase, privateKeyPEM);

      responseHeaders['Signature-Input'] = signatureInputString;
      responseHeaders['Signature'] = `sig1=:${signature}:`;

      console.log(`Successfully signed with NTP time. Timestamp sent: ${created}`);
      res.status(200).json(responseHeaders);

    } catch (error) {
      console.error('Error during signing process:', error.message);
      res.status(500).json({ error: error.message });
    }
  });
});

app.post('/sign-sdk', (req, res) => {
    try {
        // LOGGING: Log the start of a new request
        console.log("\n--- New Signing Request Received ---");

        const { keys } = req.body;
        if (!keys || !keys.jwe || !keys.privatekey) {
            console.error("ERROR: Request body was missing 'keys', 'jwe', or 'privatekey'.");
            return res.status(400).json({
                error: "Request body must include a 'keys' object with 'jwe' and 'privatekey'."
            });
        }
        
        // LOGGING: Confirm that keys were received without logging the actual secret key
        console.log(`[1/5] Keys received. JWE present: ${!!keys.jwe}, Private Key present: ${!!keys.privatekey}`);

        // --- URL Construction Logic ---
        const baseUrl = 'https://api.ebay.com/sell/finances/v1/transaction';
        const startDate = DateTime.now().setZone('utc').minus({ weeks: 1 }).toISO();
        const endDate = DateTime.now().setZone('utc').toISO();
        const filterValue = `transactionDate:[${startDate}..${endDate}]`;
        const typeValue = '{SALE,REFUND}';
        const finalUrl = `${baseUrl}?filter=${encodeURIComponent(filterValue)}&transactionType=${encodeURIComponent(typeValue)}`;

        // LOGGING: Log the URL that will be used for the signature
        console.log(`[2/5] Generated URL for signing: ${finalUrl}`);

        // --- Use the SDK for Signing ---
        const config = {
            privateKey: `-----BEGIN PRIVATE KEY-----\n${keys.privatekey}\n-----END PRIVATE KEY-----`,
            signatureParams: [
                'x-ebay-signature-key',
                '@method',
                '@path',
                '@authority'
            ]
        };

        const parsedUrl = new URL(finalUrl);
        const signingData = {
            '@method': 'GET',
            '@path': parsedUrl.pathname + parsedUrl.search,
            '@authority': parsedUrl.host,
            'x-ebay-signature-key': keys.jwe
        };

        // LOGGING: Log the exact data being passed to the SDK
        console.log('[3/5] Data being passed to eBay SDK:', JSON.stringify(signingData, null, 2));

        const signatureInput = ebaySignature.generateSignatureInput(signingData, config);
        const signature = ebaySignature.generateSignature(signingData, config);

        // LOGGING: Log the output from the SDK
        console.log(`[4/5] SDK generated Signature-Input: ${signatureInput}`);
        console.log(`[4/5] SDK generated Signature: ${signature}`);


        // --- Prepare Final Response ---
        const responseHeaders = {
            'x-ebay-signature-key': keys.jwe,
            'Signature-Input': signatureInput,
            'Signature': signature,
            'url': finalUrl
        };

        // LOGGING: Log the complete object being sent back to n8n
        console.log('[5/5] Final response object sent to n8n:', JSON.stringify(responseHeaders, null, 2));
        console.log("--- Request Finished Successfully ---\n");
        
        res.status(200).json(responseHeaders);

    } catch (error) {
        console.error('--- ERROR during signing process ---');
        console.error(error.stack);
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`✅ SDK-based Sign server with logging listening on port ${port}`);
});
