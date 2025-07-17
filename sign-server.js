import express from 'express';
import bodyParser from 'body-parser';
import { signMessage } from 'digital-signature-nodejs-sdk';

const app = express();
app.use(bodyParser.json());

// the exact list of headers/pseudo‑headers we sign:
const SIGNATURE_PARAMS = [
  '(request-target)',
  'host',
  'date',
  'content-digest',
  'x-ebay-signature-key',
];

app.post('/sign', async (req, res) => {
  try {
    // 1) Pull in the incoming HTTP‐call details
    const { method, url: rawUrl, headers = {}, body = '' } = req.body;

    // 2) Normalize to a full URL + path
    const fullUrl = rawUrl.startsWith('http')
      ? rawUrl
      : `https://apiz.ebay.com${rawUrl}`;
    const { pathname, search, host } = new URL(fullUrl);
    const path = pathname + (search || '');

    // 3) Ensure host & date headers exist
    const date = new Date().toUTCString();
    headers.host = headers.host || host;
    headers.date = headers.date || date;

    // 4) Build the components object (SDK will fill date & digest)
    const signatureComponents = {
      '(request-target)':    `${method.toLowerCase()} ${path}`,
      host:                  headers.host,
      date:                  '',                // ← SDK auto‑populates
      'content-digest':      '',                // ← SDK auto‑populates
      'x-ebay-signature-key': process.env.EBAY_JWE
    };

    // 5) Single‐object call with ALL config in v3.x
    const result = await signMessage({
      method,
      url: fullUrl,
      headers,
      body,
      key: {
        id:         process.env.EBAY_KEY_ID,
        privateKey: process.env.EBAY_PRIVATE_KEY,
        algorithm:  'ed25519'
      },
      // ─── all these MUST be top‐level props for v3.x ───
      jwe:                  process.env.EBAY_JWE,
      digestAlgorithm:      'sha256',
      signatureParams:      SIGNATURE_PARAMS,
      signatureComponents,  // shorthand for the object above
      addMissingHeaders:    true
    });

    // 6) Return just the four signature headers (plus Date)
    return res.json({
      'Signature':            result.signatureHeader,
      'Signature-Input':      result.signatureInputHeader,
      'Content-Digest':       result.digestHeader,
      'x-ebay-signature-key': process.env.EBAY_JWE,
      'Date':                 date
    });
  } catch (err) {
    console.error('Signer error:', err);
    return res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer API listening on port ${PORT}`));
