import express from 'express';
import bodyParser from 'body-parser';
import { signMessage } from 'digital-signature-nodejs-sdk';

const app = express();
app.use(bodyParser.json());

// ⚠️ Make sure these ENV vars are set in Render or Railway
const keyId = process.env.EBAY_KEY_ID;          // Example: "abcde=="
const privateKey = process.env.EBAY_PRIVATE_KEY; // Your ED25519 private key
const jwe = process.env.EBAY_JWE;                // Your eBay JWE

app.post('/sign', async (req, res) => {
  try {
    const { method, url, headers = {}, body = '' } = req.body;

    const result = await signMessage({
      method,
      url,
      headers,
      body,
      key: {
        id: keyId,
        privateKey,
        algorithm: 'ed25519'
      },
      options: {
        addMissingHeaders: true, // Auto-add Date, Host, etc.
        jwe
      }
    });

    return res.json({
      'Signature': result.signatureHeader,
      'Signature-Input': result.signatureInputHeader,
      'Content-Digest': result.digestHeader,
      'x-ebay-signature-key': jwe,
      'Date': result.headers.date
    });
  } catch (err) {
    console.error('Signer error:', err);
    return res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Signer API listening on port ${PORT}`);
});
