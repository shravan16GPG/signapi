import ntpClient from 'ntp-client'; // <-- ADD THIS IMPORT AT THE TOP

// ... (your other code)

// --- Signer Endpoint (FINAL ROBUST VERSION WITH NTP) ---
app.post('/sign', (req, res) => { // NOTE: Removed async here, will use promises
  ntpClient.getNetworkTime("a.st1.ntp.br", 123, (err, date) => {
    if (err) {
      console.error("NTP Error:", err);
      // Fallback to system time if NTP fails, but log it
      date = new Date(); 
    }

    try {
      const { method, url, keys, body } = req.body;
      if (!method || !url || !keys || !keys.jwe || !keys.privatekey) {
        return res.status(400).json({ 
          error: "Request body must include 'method', 'url', and a 'keys' object with 'jwe' and 'privatekey'." 
        });
      }

      // USE THE TIME FROM NTP
      const created = Math.floor(date.getTime() / 1000); 

      const parsedUrl = new URL(url);
      const methodUpper = method.toUpperCase();
      const responseHeaders = {'x-ebay-signature-key': keys.jwe};
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
      if (digest) { signatureBaseLines.push(`"content-digest": ${digest}`); }
      signatureBaseLines.push(`"x-ebay-signature-key": ${keys.jwe}`);
      signatureBaseLines.push(`"@method": ${methodUpper}`);
      const pathWithQuery = parsedUrl.pathname + parsedUrl.search;
      signatureBaseLines.push(`"@path": ${pathWithQuery}`);
      signatureBaseLines.push(`"@authority": ${parsedUrl.host}`);
      signatureBaseLines.push(`"@signature-params": ${signatureInputString}`);
      const signatureBase = signatureBaseLines.join('\n');
      const privateKeyPEM = formatPrivateKeyToPEM(keys.privatekey);
      const signature = signEd25519(signatureBase, privateKeyPEM);

      responseHeaders['Signature-Input'] = signatureInputString;
      responseHeaders['Signature'] = `sig1=:${signature}:`;
      
      console.log(`Successfully signed with NTP time. Timestamp sent: ${created}`);
      res.status(200).json(responseHeaders);

    } catch (error) {
      console.error('Error during signing process:', error);
      res.status(500).json({ error: error.message });
    }
  });
});