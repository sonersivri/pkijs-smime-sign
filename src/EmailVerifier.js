import React, { useState } from 'react';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as pvutils from "pvutils";
import parse from "emailjs-mime-parser";

const EmailVerifier = () => {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');

  const verifyEmail = async () => {
    try {
      const parser = parse(email);
      if (!("childNodes" in parser) || (parser.childNodes.length !== 2)) {
        alert("No S/MIME signature found in the email. 1");
        return;
      }
      console.log(parser.childNodes[0].raw)
      const lastNode = parser.childNodes[1];
      if (!lastNode || !("contentType" in lastNode) || (lastNode.contentType.value !== "application/x-pkcs7-signature" && lastNode.contentType.value !== "application/pkcs7-signature")) {
        alert("No S/MIME signature found in the email. 2");
        return;
      }
  
      // Check if it's a signed message
  
      // Step 2: Parse the signature using ASN.1
      const signatureAsn1 = asn1js.fromBER(lastNode.content.buffer);
      const cmsContentSimpl = new pkijs.ContentInfo({ schema: signatureAsn1.result });
      const signedData = new pkijs.SignedData({ schema: cmsContentSimpl.content });
  
      // Step 3: Get the signer's certificate and verify the signature
      const certificate = signedData.certificates[0];
      const signer = signedData.signerInfos[0];
  
      // Import the certificate and verify the signature
      
      const signedDataBuffer = pvutils.stringToArrayBuffer(parser.childNodes[0].raw.replace(/\n/g, "\r\n"));
      alert(signedData.certificates[0].serialNumber);
      alert(signedData.signerInfos[0].sid.serialNumber);
      const verified = await signedData.verify({
          signer: 0,
          data: signedDataBuffer,  // Use plain text or HTML content as appropriate
          trustedCerts: []
      });

      alert("verfied: " + verified)
    } catch (err) {
      alert('Error signing email:' + err);
      setError('Failed to sign email. Please check the console for more details.');
    }
  };

  return (
    <div>
      <h1>Email Verifier</h1>
      <textarea 
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter email content"
        style={{ width: '200%', height: '300px' }} // Set width and height here
      />
      <button onClick={verifyEmail}>Verify Email</button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default EmailVerifier;