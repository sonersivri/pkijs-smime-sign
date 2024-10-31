import React, { useState } from 'react';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as pvutils from "pvutils";

const EmailSigner = () => {
  const [email, setEmail] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [certificate, setCertificate] = useState('');
  const [caCertificate, setCaCertificate] = useState('');
  const [error, setError] = useState('');
  const [signature, setSignature] = useState('');

  const signEmail = async () => {
    try {
      
      const rawEmail = email.replace(/\n/g, "\r\n");

      const lines = rawEmail.split("\r\n");
      let isHeader = true;
      let headers = '';
      let body = '';
      for (const line of lines) {
        if (line.trim() === "\r\n" || line.trim() === "") {
          isHeader = false;
        } else if (isHeader && line.startsWith("Content-Type:")) {
          body = line + "\r\n";
        } else if (isHeader) {
          headers += line + "\r\n";
        } else {
          body += line + "\r\n";
        }
      }

      console.log(headers);

      console.log(body);

      
      const str = pvutils.stringToArrayBuffer(body);

      

      const cert = certificate
        .replace(/-----BEGIN CERTIFICATE-----/, "")
        .replace(/-----END CERTIFICATE-----/, "")
        .replace(/\s+/g, "");

      const binaryDer2 = Uint8Array.from(atob(cert), (char) => char.charCodeAt(0));

      // 2. Parse the binary DER data using asn1js
      const asn12 = asn1js.fromBER(binaryDer2.buffer);
      if (asn12.offset === -1) {
        throw new Error("Failed to parse certificate");
      }

      const cacert = caCertificate
        .replace(/-----BEGIN CERTIFICATE-----/, "")
        .replace(/-----END CERTIFICATE-----/, "")
        .replace(/\s+/g, "");

      const binaryDer3 = Uint8Array.from(atob(cacert), (char) => char.charCodeAt(0));

      // 2. Parse the binary DER data using asn1js
      const asn13 = asn1js.fromBER(binaryDer3.buffer);
      if (asn13.offset === -1) {
        throw new Error("Failed to parse certificate");
      }


  // 3. Initialize a pkijs Certificate object from the ASN.1 structure
      const certificatex = new pkijs.Certificate({ schema: asn12.result });
      const certificateca = new pkijs.Certificate({ schema: asn13.result });

      const cmsSigned = new pkijs.SignedData({
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
          eContentType: "1.2.840.113549.1.7.1", // data type
          eContent: new asn1js.OctetString({ valueHex: str }),
        }),
        signerInfos: [
          new pkijs.SignerInfo({
            sid: new pkijs.IssuerAndSerialNumber({
              issuer: certificatex.issuer,
              serialNumber: certificatex.serialNumber,
            }),
          }),
        ],
      });

      cmsSigned.certificates = [certificatex, certificateca];
      

      const pem = privateKey
        .replace(/-----BEGIN PRIVATE KEY-----/, "")
        .replace(/-----END PRIVATE KEY-----/, "")
        .replace(/\s+/g, "");
      const binaryDerString = atob(pem); // base64 decode
      const binaryDer = new Uint8Array(
        [...binaryDerString].map((char) => char.charCodeAt(0))
      );

      // 2. Import the key to a CryptoKey object
      const cryptoKey = await window.crypto.subtle.importKey(
        "pkcs8", // Format of the key
        binaryDer.buffer,
        {
          name: "RSA-PSS", // Algorithm to use with the key (or RSA-OAEP, etc.)
          hash: "SHA-256", // Hash algorithm
        },
        true, // Key can be exported
        ["sign"] // Key usage
      );

      await cmsSigned.sign(cryptoKey, 0, "SHA-256");
      
      const cmsContentInfo = new pkijs.ContentInfo({
        contentType: "1.2.840.113549.1.7.2", // signedData type
        content: cmsSigned.toSchema(),
      });
      const cmsSignedBuffer = cmsContentInfo.toSchema().toBER(false);
      const signedBoundy = "------------carbonioSigned" + Date.now();
      const signedBoundrySeparater = "--" + signedBoundy;
      const signature = btoa(String.fromCharCode(...new Uint8Array(cmsSignedBuffer)));
      const formattedSignature = signature.match(/.{1,72}/g).join("\r\n");
      const signedEmail = [
        headers + 'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="' +  signedBoundy + '"',
        "",
        "This is a cryptographically signed message in MIME format.",
        "",
        signedBoundrySeparater,
        body,
        signedBoundrySeparater,
        'Content-Type: application/pkcs7-signature; name="smime.p7s"',
        'Content-Transfer-Encoding: base64',
        'Content-Disposition: attachment; filename="smime.p7s"',
        'Content-Description: S/MIME Cryptographic Signature',
        "",
        formattedSignature,
        signedBoundrySeparater + "--",
      ].join("\r\n");
      setSignature(signedEmail);


    } catch (err) {
      alert('Error signing email:' + err);
      setError('Failed to sign email. Please check the console for more details.');
    }
  };

  return (
    <div>
      <h1>Email Signer</h1>
      <textarea 
        value={privateKey}
        onChange={(e) => setPrivateKey(e.target.value)}
        placeholder="Enter Private Key content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <textarea 
        value={certificate}
        onChange={(e) => setCertificate(e.target.value)}
        placeholder="Enter Certificate content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />

<textarea 
        value={caCertificate}
        onChange={(e) => setCaCertificate(e.target.value)}
        placeholder="Enter CA Certificate content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <textarea 
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter email content"
        style={{ width: '200%', height: '200px' }} // Set width and height here
      />
      <button onClick={signEmail}>Sign Email</button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <textarea readOnly value={signature} style={{ width: '100%', height: '200px' }} />
    </div>
  );
};

export default EmailSigner;