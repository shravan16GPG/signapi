import express from 'express';
import bodyParser from 'body-parser';
import { signMessage } from 'digital-signature-nodejs-sdk';

const app = express();
app.use(bodyParser.json());

const config = {
  digestAlgorithm: 'sha256',
  privateKey: process.env.EBAY_PRIVATE_KEY,
  jwe: process.env.EBAY_JWE,
  signatureParams: [
    '(request-target)',
    'host',
    'date',
    'content-digest',
    'x-ebay-signature-key'
  ],
  signatureComponents: {
    '(request-target)': 'get /sell/finances/v1/transaction',
    host: 'apiz.ebay.com',
    date: '',
    'content-digest': '',
    'x-ebay-signature-key': process.env.EBAY_JWE
  }
};

app.post('/sign', async (req, res) => {
  try {
    const result = await signMessage({
      method: 'GET',
      url: 'https://apiz.ebay.com/sell/finances/v1/transaction',
      headers: {
        host: 'apiz.ebay.com',
        date: new Date().toUTCString()
      },
      body: ''
    }, config);

    res.json({
      'Signature': result.signatureHeader,
      'Signature-Input': result.signatureInputHeader,
      'Content-Digest': result.digestHeader,
      'x-ebay-signature-key': config.jwe,
      'Date': result.headers.date
    });
  } catch (err) {
    res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Signer API listening on port ${PORT}`);
});
