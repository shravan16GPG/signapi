import express from 'express';
import bodyParser from 'body-parser';
import { signMessage } from 'digital-signature-nodejs-sdk';

const app = express();
app.use(bodyParser.json());

app.post('/sign', async (req, res) => {
  try {
    const date = new Date().toUTCString();

    const result = await signMessage({
      method: 'GET',
      url: 'https://apiz.ebay.com/sell/finances/v1/transaction',
      headers: {
        host: 'apiz.ebay.com',
        date,
      },
      body: '',
      key: {
        id: process.env.EBAY_KEY_ID,
        privateKey: process.env.EBAY_PRIVATE_KEY,
        algorithm: 'ed25519',
      },
      options: {
        jwe: process.env.EBAY_JWE,
        addMissingHeaders: true,
      }
    });

    res.json({
      'Signature': result.signatureHeader,
      'Signature-Input': result.signatureInputHeader,
      'Content-Digest': result.digestHeader,
      'x-ebay-signature-key': process.env.EBAY_JWE,
      'Date': date
    });
  } catch (err) {
    res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Signer API listening on port ${PORT}`);
});
