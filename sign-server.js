// sign-server.js
// Contains the original /sign endpoint and the new, corrected /sign-sdk endpoint.

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import base64url from 'base64url';
import crypto from 'crypto';
import { URL } from 'url';
import ntpClient from 'ntp-client';
// --- Add new dependencies for the /sign-sdk endpoint ---
import { DateTime } from 'luxon';
import ebaySignature from 'digital-signature-nodejs-sdk';


const app = express();
const port = process.env.PORT || 3000;

// --- Middleware Setup ---
app.use(cors());
app.use(bodyParser.json());


// --- Utility Functions from Original Code ---
function sha256Digest(payload) {
  const hash = crypto.createHash('sha256');
  hash.update(payload, 'utf8');
  return `sha-256=:${hash.digest('base64')}:`;
}

function formatPrivateKeyToPEM(rawKey) {
  return `-----BEGIN PRIVATE KEY-----\n${rawKey}\n-----END PRIVATE KEY-----`;
}

function signEd25519(base, privateKeyPem) {
  try {
    const key = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: 'sec1'
    });
    const sign = crypto.sign(null, Buffer.from(base, 'utf8'), key);
    return base64url.encode(sign);
  } catch (e) {
    console.error("Error creating private key. Check if the key format is correct.", e);
    throw e;
  }
}


// --- Original /sign Endpoint (Unchanged) ---
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


// --- NEW, CORRECTED /sign-sdk endpoint ---
app.post('/sign-sdk', (req, res) => {
    try {
        console.log("\n--- New SDK Signing Request Received ---");
        const { keys } = req.body;

        if (!keys || !keys.jwe || !keys.privatekey) {
            throw new Error("Request must include JWE and Private Key in the 'keys' object.");
        }

        const JWE = keys.jwe;
        const PRIVATE_KEY = keys.privatekey;

        const baseUrl = 'https://api.ebay.com/sell/finances/v1/transaction';
        const startDate = DateTime.now().setZone('utc').minus({ weeks: 1 }).toISO();
        const endDate = DateTime.now().setZone('utc').toISO();
        const filterValue = `transactionDate:[${startDate}..${endDate}]`;
        const typeValue = '{SALE,REFUND}';
        const finalUrl = `${baseUrl}?filter=${encodeURIComponent(filterValue)}&transactionType=${encodeURIComponent(typeValue)}`;
        const parsedUrl = new URL(finalUrl);
        
        console.log(`[INFO] Using URL: ${finalUrl}`);

        const config = {
            privateKey: `-----BEGIN PRIVATE KEY-----\n${PRIVATE_KEY}\n-----END PRIVATE KEY-----`,
            signatureParams: [
                'x-ebay-signature-key',
                '@method',
                '@path',
                '@authority'
            ],
            signatureComponents: {
                '@method': 'GET',
                '@path': parsedUrl.pathname + parsedUrl.search,
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

        console.log("\n✅ --- SUCCESS: Signature Generated --- ✅");
        res.status(200).json(finalResponse);

    } catch (error) {
        console.error('\n❌ --- SCRIPT FAILED --- ❌');
        console.error(error.stack);
        res.status(500).json({ error: error.message });
    }
});


// --- Server Start ---
app.listen(port, () => {
  console.log(`✅ Sign server listening on http://localhost:${port}`);
});