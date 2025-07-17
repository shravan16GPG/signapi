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

const SIGNATURE_PARAMS = [
  '(request-target)',
  'host',
  'date',
  'content-digest',
  'x-ebay-signature-key',
];

app.post('/sign', (req, res) => {
  try {
    // 1) Extract request details
    const { method, url: rawUrl, headers = {}, body = '' } = req.body;

    // 2) Build full URL & path
    const fullUrl = rawUrl.startsWith('http')
      ? rawUrl
      : `https://apiz.ebay.com${rawUrl}`;
    const { pathname, search, host } = new URL(fullUrl);
    const path = pathname + (search || '');

    // 3) Ensure required headers
    const dateHeader = new Date().toUTCString();
    headers.host = headers.host || host;
    headers.date = headers.date || dateHeader;

    // 4) Generate Content-Digest header
    //    e.g. "sha-256=BASE64_DIGEST"
    const digestHeader = generateDigestHeader('sha256', body);

    // 5) Build signatureComponents map
    const signatureComponents = {
      '(request-target)':    `${method.toLowerCase()} ${path}`,
      host:                  headers.host,
      date:                  headers.date,
      'content-digest':      digestHeader,
      'x-ebay-signature-key': process.env.EBAY_JWE,
    };

    // 6) Generate Signature-Input header
    const signatureInput = generateSignatureInput(
      SIGNATURE_PARAMS,
      signatureComponents
    );

    // 7) Generate the raw signature (ED25519)
    const signature = generateSignature(
      signatureInput,
      process.env.EBAY_PRIVATE_KEY,
      'ed25519'
    );

    // 8) Generate the JWE key header value
    const signatureKey = generateSignatureKey(process.env.EBAY_JWE);

    // 9) Return the four headers
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
app.listen(PORT, () => console.log(`Signer API listening on port ${PORT}`));
