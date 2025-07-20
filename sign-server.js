// sign-server.js
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import base64url from 'base64url';
import crypto from 'crypto';
import { URL } from 'url';

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// --- Use your actual keys from eBay's Key Management API ---
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEK2gBsjjGPUtvqQwzPq9rPrAIF6bJFFuFlrwptJFzez
-----END PRIVATE KEY-----`;

// This is your Public Key as JWE
const JWE = 'eyJ6aXAiOiJERUYiLCJraWQiOiJhZjE4NDE3NC0wMjg2LTQ2OWQtOWJhZi04MmM3NWFmZDIwZDUiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiNkU5eUh0bTQ1NGJsd29VNEZIX25qUSIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiVHJhblg4MmxiZ1hPMXMyRCJ9.9eJw-UP6A3y6scucEjE9GV1TAHKTa_D89BE3o4lI5KY.o-XDrDAV9y8Uph9W.ja3pYILXmZb4lh3ngP7ppFz12GZnBYbDfH_9ryRU1IUS05HDNg1koLPgk-sxHTtifc96bZ8BeZigFWKgV8PNyUvn8u5H1j3cD8i5aZbvbfYTsENA07NTxtWpo_j5CQnv319dUo1YyWCglVs60hHwW7dp20oN9mctQ2rV32EhuA8TRahfq_fZ397m90SzYH09P-zrKwB8MT11W1HBJ-BW2uXPZhwfmVG2ZUXnAtfP0pttXwtyo-49uSJkh0cycap-joXL297bZNU.PO3pt2dG9Xc6Vrr01S0fgw';

// --- Utility Functions ---
function sha256Digest(payload) {
  const hash = crypto.createHash('sha256');
  hash.update(payload, 'utf8'); // Specify encoding
  return `sha-256=:${hash.digest('base64')}:`;
}

function createSignatureInput(headers, created) {
  const headerList = headers.map(h => `"${h}"`).join(' ');
  return `sig1=(${headerList});created=${created}`;
}

// NOTE: The buildSignatureBase in the original question was flawed.
// This is not actually needed if we construct the base string directly.
function signEd25519(base, privateKeyPem) {
  const key = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem', type: 'pkcs8' });
  const sign = crypto.sign(null, Buffer.from(base, 'utf8'), key);
  return base64url.encode(sign);
}


// --- Signer Endpoint ---
app.post('/sign', async (req, res) => {
  try {
    const { url, method, body } = req.body;
    if (!url || !method) {
        return res.status(400).json({ error: "url and method are required." });
    }
    const parsedUrl = new URL(url);

    const methodUpper = method.toUpperCase(); // FIX 2: Use uppercase method (GET, POST)
    const created = Math.floor(Date.now() / 1000);
    
    let digest = null;
    // Base headers for all requests
    const coveredComponents = ['"x-ebay-signature-key"', '"@method"', '"@path"', '"@authority"'];
    
    // Add content-digest ONLY for requests with a body
    if (["POST", "PUT", "PATCH"].includes(methodUpper) && body) {
      digest = sha256Digest(JSON.stringify(body));
      coveredComponents.unshift('"content-digest"'); // Add to the beginning of the list
    }

    // --- Build the Signature Base String ---
    const signatureBaseLines = [];
    if (digest) {
        signatureBaseLines.push(`"content-digest": ${digest}`);
    }
    signatureBaseLines.push(`"x-ebay-signature-key": ${JWE}`);
    signatureBaseLines.push(`"@method": ${methodUpper}`);
    // FIX 1: Use pathname + search to include the query string
    const pathWithQuery = parsedUrl.pathname + parsedUrl.search;
    signatureBaseLines.push(`"@path": ${pathWithQuery}`);
    signatureBaseLines.push(`"@authority": ${parsedUrl.host}`);

    const signatureInputString = `sig1=(${coveredComponents.join(' ')});created=${created}`;
    signatureBaseLines.push(`"@signature-params": ${signatureInputString}`);

    const signatureBase = signatureBaseLines.join('\n');
    
    console.log("--- Generated Signature Base ---");
    console.log(signatureBase);
    console.log("------------------------------");

    // --- Sign the Base String ---
    const signature = signEd25519(signatureBase, PRIVATE_KEY);

    // --- Construct Final Headers ---
    const responseHeaders = {
      'x-ebay-signature-key': JWE,
      'Signature-Input': signatureInputString,
      'Signature': `sig1=:${signature}:`,
    };

    if (digest) {
      responseHeaders['Content-Digest'] = digest;
    }

    res.status(200).json(responseHeaders);

  } catch (error) {
    console.error('Error signing request:', error);
    res.status(500).json({ error: error.message });
  }
});

// --- Server ---
app.listen(port, () => {
  console.log(`✅ Sign server listening on http://localhost:${port}`);
});