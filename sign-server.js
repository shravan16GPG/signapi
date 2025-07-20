// sign-server.js
// ... (keep all the other code, like express, cors, utility functions, etc.)

// --- Utility function to format the private key ---
function formatPrivateKeyToPEM(rawKey) {
  return `-----BEGIN PRIVATE KEY-----\n${rawKey}\n-----END PRIVATE KEY-----`;
}

// --- Signer Endpoint (FINAL REVISED VERSION) ---
app.post('/sign', async (req, res) => {
  try {
    // We expect method, url, and keys in the request body
    const { method, url, keys, body } = req.body;

    if (!method || !url || !keys || !keys.jwe || !keys.privatekey) {
      return res.status(400).json({ 
        error: "Request body must include 'method', 'url', and a 'keys' object with 'jwe' and 'privatekey'." 
      });
    }

    const parsedUrl = new URL(url);
    const methodUpper = method.toUpperCase();
    const created = Math.floor(Date.now() / 1000);

    const responseHeaders = {
      'x-ebay-signature-key': keys.jwe
    };

    let digest = null;
    let coveredComponents = ['"x-ebay-signature-key"', '"@method"', '"@path"', '"@authority"'];
    
    if (["POST", "PUT", "PATCH"].includes(methodUpper)) {
      const payload = body ? JSON.stringify(body) : '{}';
      digest = sha256Digest(payload);
      responseHeaders['Content-Digest'] = digest;
      coveredComponents.unshift('"content-digest"');
    }

    const signatureInputString = `sig1=(${coveredComponents.join(' ')});created=${created}`;
    
    const signatureBaseLines = [];
    if (digest) {
        signatureBaseLines.push(`"content-digest": ${digest}`);
    }
    signatureBaseLines.push(`"x-ebay-signature-key": ${keys.jwe}`);
    signatureBaseLines.push(`"@method": ${methodUpper}`);
    const pathWithQuery = parsedUrl.pathname + parsedUrl.search;
    signatureBaseLines.push(`"@path": ${pathWithQuery}`);
    signatureBaseLines.push(`"@authority": ${parsedUrl.host}`);
    signatureBaseLines.push(`"@signature-params": ${signatureInputString}`);

    const signatureBase = signatureBaseLines.join('\n');

    // Convert the raw private key to PEM format before signing
    const privateKeyPEM = formatPrivateKeyToPEM(keys.privatekey);
    const signature = signEd25519(signatureBase, privateKeyPEM);

    responseHeaders['Signature-Input'] = signatureInputString;
    responseHeaders['Signature'] = `sig1=:${signature}:`;

    res.status(200).json(responseHeaders);

  } catch (error) {
    console.error('Error signing request:', error);
    res.status(500).json({ error: error.message });
  }
});

// ... (keep the app.listen part) ...