import express from 'express';
import bodyParser from 'body-parser';
import { signMessage } from 'digital-signature-nodejs-sdk';

const app = express();
app.use(bodyParser.json());

const CONFIG = {
  // from example-config.json
  digestAlgorithm: 'sha256',
  jwe:             process.env.EBAY_JWE,
  privateKey:      process.env.EBAY_PRIVATE_KEY,
  signatureParams: [
    '(request-target)',
    'host',
    'date',
    'content-digest',
    'x-ebay-signature-key'
  ],
  signatureComponents: {
    '(request-target)': '',   // filled in below
    host:                  '',// filled in below
    date:                  '',// SDK will fill after header injection
    'content-digest':      '',// SDK will fill
    'x-ebay-signature-key': process.env.EBAY_JWE
  }
};

app.post('/sign', async (req, res) => {
  try {
    const { method, url, headers = {}, body = '' } = req.body;

    // 1) Normalize full URL
    const fullUrl = url.startsWith('http')
      ? url
      : `https://apiz.ebay.com${url}`;

    // 2) Inject required headers if missing
    const date = new Date().toUTCString();
    headers.host = headers.host || new URL(fullUrl).host;
    headers.date = headers.date || date;

    // 3) Prepare signatureComponents that depend on method+path
    const parsed = new URL(fullUrl);
    const path = parsed.pathname + (parsed.search || '');
    CONFIG.signatureComponents['(request-target)'] = `${method.toLowerCase()} ${path}`;
    CONFIG.signatureComponents.host = headers.host;

    // 4) Call SDK in payload+config mode
    const result = await signMessage(
      { method, url: fullUrl, headers, body },
      CONFIG
    );

    // 5) Return exactly the headers n8n needs
    return res.json({
      'Signature':             result.signatureHeader,
      'Signature-Input':       result.signatureInputHeader,
      'Content-Digest':        result.digestHeader,
      'x-ebay-signature-key':  process.env.EBAY_JWE,
      'Date':                  date
    });
  } catch (err) {
    console.error('Signer error:', err);
    return res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer API listening on port ${PORT}`));
