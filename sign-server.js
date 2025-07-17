import express from 'express';
import bodyParser from 'body-parser';
import { signMessage } from 'digital-signature-nodejs-sdk';

const app = express();
app.use(bodyParser.json());

const SIGNATURE_PARAMS = [
  '(request-target)',
  'host',
  'date',
  'content-digest',
  'x-ebay-signature-key',
];

app.post('/sign', async (req, res) => {
  try {
    const { method, url: rawUrl, headers = {}, body = '' } = req.body;

    // 1️⃣ Build full URL & parse path
    const fullUrl = rawUrl.startsWith('http')
      ? rawUrl
      : `https://apiz.ebay.com${rawUrl}`;
    const { pathname, search, host } = new URL(fullUrl);
    const path = pathname + (search || '');

    // 2️⃣ Ensure required headers
    const date   = new Date().toUTCString();
    headers.host = headers.host || host;
    headers.date = headers.date || date;

    // 3️⃣ Build signatureComponents
    const signatureComponents = {
      '(request-target)': `${method.toLowerCase()} ${path}`,
      host:               headers.host,
      date:               '',    // SDK will fill in
      'content-digest':   '',    // SDK will fill in
      'x-ebay-signature-key': process.env.EBAY_JWE,
    };

    // 4️⃣ Single-object call to signMessage()
    const result = await signMessage({
      method,
      url: fullUrl,
      headers,
      body,
      // core config:
      digestAlgorithm: 'sha256',
      jwe:              process.env.EBAY_JWE,
      key: {
        id:           process.env.EBAY_KEY_ID,
        privateKey:   process.env.EBAY_PRIVATE_KEY,
        algorithm:    'ed25519',
      },
      signatureParams,
      signatureComponents,
    });

    // 5️⃣ Send back exactly the headers you need
    return res.json({
      'Signature':            result.signatureHeader,
      'Signature-Input':      result.signatureInputHeader,
      'Content-Digest':       result.digestHeader,
      'x-ebay-signature-key': process.env.EBAY_JWE,
      'Date':                 date,
    });
  } catch (err) {
    console.error('Signer error:', err);
    return res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer API listening on port ${PORT}`));
