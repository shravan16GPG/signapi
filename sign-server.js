import express from 'express';
import bodyParser from 'body-parser';
import {
  generateDigestHeader,
  generateSignatureInput,
  generateSignature,
  generateSignatureKey,
} from 'digital-signature-nodejs-sdk';

const app = express();
app.use(bodyParser.json());

// The exact headers and pseudo-headers to include in the signature
const SIGNATURE_PARAMS = [
  '(request-target)',
  'host',
  'date',
  'content-digest',
  'x-ebay-signature-key',
];

app.post('/sign', (req, res) => {
  try {
    // 1) Extract HTTP call details from request body
    const { method, url: rawUrl, headers = {}, body = '' } = req.body;

    // 2) Normalize URL and extract path
    const fullUrl = rawUrl.startsWith('http')
      ? rawUrl
      : `https://apiz.ebay.com${rawUrl}`;
    const { pathname, search, host } = new URL(fullUrl);
    const path = pathname + (search || '');

    // 3) Ensure required headers exist
    const dateHeader = new Date().toUTCString();
    headers.host = headers.host || host;
    headers.date = headers.date || dateHeader;

    // 4) Generate the Content-Digest header (RFC 9530)
    //    Note: use 'sha-256' (with dash) here
    const digestHeader = generateDigestHeader('sha-256', body);

    // 5) Build signatureComponents for Signature-Input (RFC 9421)
    const signatureComponents = {
      '(request-target)':    `${method.toLowerCase()} ${path}`,
      host:                  headers.host,
      date:                  headers.date,
      'content-digest':      digestHeader,
      'x-ebay-signature-key': process.env.EBAY_JWE,
    };

    // 6) Create the Signature-Input header
    const signatureInput = generateSignatureInput(
      SIGNATURE_PARAMS,
      signatureComponents
    );

    // 7) Generate the ED25519 signature over the signing string
    const signature = generateSignature(
      signatureInput,
      process.env.EBAY_PRIVATE_KEY,
      'ed25519'
    );

    // 8) Create the x-ebay-signature-key header value (JWE)
    const signatureKey = generateSignatureKey(process.env.EBAY_JWE);

    // 9) Return the four required signature headers (plus Date)
    return res.json({
      'Content-Digest':       digestHeader,
      'Signature-Input':      signatureInput,
      'Signature':            signature,
      'x-ebay-signature-key': signatureKey,
      'Date':                 dateHeader,
    });
  } catch (err) {
    console.error('Signer error:', err);
    return res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Signer API listening on port ${PORT}`)
);
