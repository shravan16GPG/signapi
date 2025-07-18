// sign-server.js
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import base64url from 'base64url';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { URL } from 'url';

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// --- Load Your Private Key and JWE from file or environment ---
//const rawBase64Key = "MC4CAQAwBQYDK2VwBCIEIEK2gBsjjGPUtvqQwzPq9rPrAIF6bJFFuFlrwptJFzez";
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEK2gBsjjGPUtvqQwzPq9rPrAIF6bJFFuFlrwptJFzez
-----END PRIVATE KEY-----`;

const privateKey = crypto.createPrivateKey({
  key: PRIVATE_KEY,
  format: 'pem',
  type: 'pkcs8',
});

const message = Buffer.from('your-message-to-sign');

const signature = crypto.sign(null, message, privateKey);
console.log('Signature:', signature.toString('base64'));
const JWE = 'eyJ6aXAiOiJERUYiLCJraWQiOiJhZjE4NDE3NC0wMjg2LTQ2OWQtOWJhZi04MmM3NWFmZDIwZDUiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiNkU5eUh0bTQ1NGJsd29VNEZIX25qUSIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiVHJhblg4MmxiZ1hPMXMyRCJ9.9eJw-UP6A3y6scucEjE9GV1TAHKTa_D89BE3o4lI5KY.o-XDrDAV9y8Uph9W.ja3pYILXmZb4lh3ngP7ppFz12GZnBYbDfH_9ryRU1IUS05HDNg1koLPgk-sxHTtifc96bZ8BeZigFWKgV8PNyUvn8u5H1j3cD8i5aZbvbfYTsENA07NTxtWpo_j5CQnv319dUo1YyWCglVs60hHwW7dp20oN9mctQ2rV32EhuA8TRahfq_fZ397m90SzYH09P-zrKwB8MT11W1HBJ-BW2uXPZhwfmVG2ZUXnAtfP0pttXwtyo-49uSJkh0cycap-joXL297bZNU.PO3pt2dG9Xc6Vrr01S0fgw'; // Your JWE envelope

// --- Utility Functions ---
function sha256Digest(payload) {
  const hash = crypto.createHash('sha256');
  hash.update(payload);
  return `sha-256=:${hash.digest('base64')}:`;
}

function createSignatureInput(headers, created) {
  const headerList = headers.map(h => `"${h}"`).join(' ');
  return `sig1=(${headerList});created=${created}`;
}

function buildSignatureBase({
  headers,
  method,
  path,
  authority,
  digest,
  jwe,
  created,
}) {
  const lines = [];
  for (const header of headers) {
    switch (header) {
      case 'content-digest':
        lines.push(`"content-digest": ${digest}`);
        break;
      case 'x-ebay-signature-key':
        lines.push(`"x-ebay-signature-key": ${jwe}`);
        break;
      case '@method':
        lines.push(`"@method": ${method.toLowerCase()}`);
        break;
      case '@path':
        lines.push(`"@path": ${path}`);
        break;
      case '@authority':
        lines.push(`"@authority": ${authority}`);
        break;
    }
  }
  lines.push(`"@signature-params": (${headers.map(h => `"${h}"`).join(' ')})` + `;created=${created}`);
  return lines.join('\n');
}

function signEd25519(base, privateKeyPem) {
  const key = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem' });
  const sign = crypto.sign(null, Buffer.from(base, 'utf8'), key);
  return base64url.encode(sign);
}

// --- Signer Endpoint ---
app.post('/sign', async (req, res) => {
  try {
    const { url, method, body } = req.body;
    const parsed = new URL(url);

    const methodLower = method.toLowerCase();
    const created = Math.floor(Date.now() / 1000);
    const headers = ['x-ebay-signature-key', '@method', '@path', '@authority'];
    let digest = null;

    if (["post", "put", "patch"].includes(methodLower)) {
      digest = sha256Digest(JSON.stringify(body || {}));
      headers.unshift('content-digest');
    }

    const signatureInput = createSignatureInput(headers, created);

    const base = buildSignatureBase({
      headers,
      method,
      path: parsed.pathname,
      authority: parsed.host,
      digest,
      jwe: JWE,
      created,
    });

    const signature = signEd25519(base, PRIVATE_KEY);

    const signatureHeaders = {
      'x-ebay-signature-key': JWE,
      'Signature': `sig1=:${signature}:`,
      'Signature-Input': signatureInput,
    };

    if (digest) {
      signatureHeaders['Content-Digest'] = digest;
    }

    res.status(200).json(signatureHeaders);
  } catch (error) {
    console.error('Error signing:', error);
    res.status(500).json({ error: error.toString() });
  }
});

// --- Server ---
app.listen(port, () => {
  console.log(`✅ Sign server listening on http://localhost:${port}`);
});
