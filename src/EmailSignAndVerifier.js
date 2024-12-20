import React, { useState } from 'react';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as pvutils from "pvutils";
import * as pvtsutils from "pvtsutils";
import forge from 'node-forge';
import parse from "emailjs-mime-parser";

const EmailSigner = () => {
  const [email, setEmail] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [certificate, setCertificate] = useState('');
  const [caCertificate, setCaCertificate] = useState('');
  const [caExtraCertificate, setExtraCertificate,] = useState('');
  const [error, setError] = useState('');
  const [signedEmail, setSignedEmail] = useState('');
  const [encryptedEmail, setEncryptedEmail] = useState('');
  const [decryptedEmail, setDecryptedEmail] = useState('');

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    const reader = new FileReader();

    reader.onload = async (e) => {
      try {
        const arrayBuffer = e.target.result;
        const password = prompt("Enter the password for the P12 file:");
        const p12Der = forge.util.createBuffer(arrayBuffer);
        const p12Asn1 = forge.asn1.fromDer(p12Der);
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

        // Extract the private key
        const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
        const keyBag = bags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
        const privateKeyObj = keyBag.key;

        // Extract the CA certificate and end-entity certificate
        const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
        const certificates = certBags[forge.pki.oids.certBag];
        if (certificates && certificates.length > 0) {
          // Assuming the first cert is the end-entity cert and the rest are CA certs
          const endEntityCert = certificates[0].cert;
          const caCerts = certificates.slice(1);

          // Convert to PEM format
          const pkcs8PrivateKey = forge.pki.privateKeyToAsn1(privateKeyObj);
        
          const pkcs8Asn1 = forge.pki.wrapRsaPrivateKey(pkcs8PrivateKey);
          const privateKeyPem = forge.pki.privateKeyInfoToPem(pkcs8Asn1);
          const endEntityCertPem = forge.pki.certificateToPem(endEntityCert);
          const caCertificatePem = caCerts.map(cert => forge.pki.certificateToPem(cert.cert)).join('\n');

          // Update the state
          setPrivateKey(privateKeyPem);
          setCertificate(endEntityCertPem);
          const caCertsArray = caCertificatePem.split('\n\n');
          setCaCertificate(caCertsArray[0]);
          if ((caCertsArray.length > 1)) {
            setExtraCertificate(caCertsArray[1]);
          }
        } else {
          alert('No certificates found in the PKCS#12 file.');
        }
      } catch (err) {
        setError('Failed to parse P12 file. Please check the console for more details.');
        console.error(err);
      }
    };


    reader.readAsArrayBuffer(file);
  };

  const signEmail = async () => {
    try {

      const rawEmail = email.replace(/\n/g, "\r\n");

      const lines = rawEmail.split("\r\n");
      let isHeader = true;
      let headers = '';
      let body = '';
      let content= '';
      for (const line of lines) {
        if (!isHeader) {
          body += line + "\r\n";
        } else if (line.trim() === "\r\n" || line.trim() === "") {
          body += "\r\n";
          isHeader = false;
        } else if (line.startsWith("Content-")) {
          body += line + "\r\n";
        } else {
          headers += line + "\r\n";
        }
      }

      const crypto = pkijs.getCrypto(true);
      const encoder = new TextEncoder();
      const data = encoder.encode(body);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      
      const certificatex = await getCertificate(certificate);
      const emailAddress = certificatex.subject.typesAndValues.map(typeAndValue => typeAndValue.value.valueBlock.value).join(", ");
      alert("Email Address from Certificate: " + emailAddress);
      const certificateca = await getCertificate(caCertificate);
      const certificateExtraca = await getCertificate(caExtraCertificate);
      const signerInfo = new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: certificatex.issuer,
          serialNumber: certificatex.serialNumber,
        }),
        signedAttrs: new pkijs.SignedAndUnsignedAttributes({
          type: 0, // Type 0 for signed attributes
          attributes: [
            new pkijs.Attribute({
              type: "1.2.840.113549.1.9.5", // OID for signing time
              values: [
                new asn1js.UTCTime({ valueDate: new Date() }) // Current date
              ]
            }),
            new pkijs.Attribute({
              type: "1.2.840.113549.1.9.3",
              values: [
                new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.1" }) // Current date
              ]
            }),
            new pkijs.Attribute({
              type: "1.2.840.113549.1.9.4",
              values: [
                new asn1js.OctetString({ valueHex: hashBuffer}) 
              ]
            }),
            // new pkijs.Attribute({
            //   type: "1.2.840.113549.1.9.15", // SMIMECapabilities OID
            //   values: [
            //     // Values that indicate specific capabilities, such as encryption or hashing algorithms
            //     new asn1js.Sequence({
            //       value: [
            //         new pkijs.SMIMECapability({
            //           capabilityID: "1.2.840.113549.3.7", // OID for TripleDES encryption
            //           parameters: new asn1js.Null() // Parameters specific to the capability
            //         }),
            //         new pkijs.SMIMECapability({
            //           capabilityID: "2.16.840.1.101.3.4.1.2", // OID for AES-128 encryption
            //           parameters: new asn1js.Null()
            //         })
            //       ]
            //     })
            //   ]
            // }),
            // new pkijs.Attribute({
            //   type: "1.3.6.1.4.1.311.16.4", // OID for signing time
            //   values: [
            //     new asn1js.OctetString({ valueDate: new Date() }) // Current date
            //   ]
            // }),
            // new pkijs.Attribute({
            //   type: "1.2.840.113549.1.9.16.2.11", // OID for signing time
            //   values: [
            //     new asn1js.UTCTime({ valueDate: new Date() }) // Current date
            //   ]
            // }),
            // new pkijs.Attribute({
            //   type: "1.2.840.113549.1.9.15", // OID for signing time
            //   values: [
            //     new asn1js.UTCTime({ valueDate: new Date() }) // Current date
            //   ]
            // }),
          ]
        })
      });
      
      const cmsSigned = new pkijs.SignedData({
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
          eContentType: "1.2.840.113549.1.7.1", // data type
        }),
        signerInfos: [signerInfo,
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
      const cryptoKey = await crypto.subtle.importKey(
        "pkcs8", // Format of the key
        binaryDer.buffer,
        {
          name: "RSASSA-PKCS1-v1_5", // Algorithm to use with the key (or RSA-OAEP, etc.)
          hash: "SHA-256", // Hash algorithm
        },
        true, // Key can be exported
        ["sign"] // Key usage
      );

      await cmsSigned.sign(cryptoKey, 0, "SHA-256", pvutils.stringToArrayBuffer(body), crypto);

      const cmsContentInfo = new pkijs.ContentInfo({
        contentType: "1.2.840.113549.1.7.2",
        content: cmsSigned.toSchema(true),
      });

      const _cmsSignedSchema = cmsContentInfo.toSchema();

  //#region Make length of some elements in "indefinite form"
      _cmsSignedSchema.lenBlock.isIndefiniteForm = true;

      const block1 = _cmsSignedSchema.valueBlock.value[1];
      block1.lenBlock.isIndefiniteForm = true;

      const block2 = block1.valueBlock.value[0];
      block2.lenBlock.isIndefiniteForm = true;
      const cmsSignedBuffer = _cmsSignedSchema.toBER(false);
      const signedBoundy = "------------carbonioSigned" + Date.now();
      const signedBoundrySeparater = "--" + signedBoundy;
      const signature = btoa(String.fromCharCode(...new Uint8Array(cmsSignedBuffer)));
      const formattedSignature = signature.match(/.{1,72}/g).join("\r\n");
      const signedEmail = [
        headers + 'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="' + signedBoundy + '"',
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
      setSignedEmail(signedEmail);
      await verifyEmail();

    } catch (err) {
      alert('Error signing email:' + err);
      setError('Failed to sign email. Please check the console for more details.');
    }

  };

  const getCertificate = async (certArg) => {
    const cert = certArg
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s+/g, "");

    const binaryDer = Uint8Array.from(atob(cert), (char) => char.charCodeAt(0));

    // 2. Parse the binary DER data using asn1js
    const asn1 = asn1js.fromBER(binaryDer.buffer);
    if (asn1.offset === -1) {
      throw new Error("Failed to parse certificate");
    }

    return new pkijs.Certificate({ schema: asn1.result });
  };

  const verifyEmail = async () => {
    try {
      const parser = parse(signedEmail);
      if (!("childNodes" in parser) || (parser.childNodes.length !== 2)) {
        alert("No S/MIME signature found in the email. 1");
        return;
      }
      const lastNode = parser.childNodes[1];
      if (!lastNode || !("contentType" in lastNode)
        || (lastNode.contentType.value !== "application/x-pkcs7-signature"
          && lastNode.contentType.value !== "application/pkcs7-signature")) {
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

  const all = async () => {
    await signEmail();
    await verifyEmail();
    await encyptEmail();
    await decyptEmail();
  }

  const encyptEmail = async () => {
    const rawEmail = email.replace(/\n/g, "\r\n");

    const lines = rawEmail.split("\r\n");
    let isHeader = true;
    let headers = '';
    let body = '';
    for (const line of lines) {
      if (!isHeader) {
        body += line + "\r\n";
      } else if (line.trim() === "\r\n" || line.trim() === "") {
        isHeader = false;
      } else if (line.startsWith("Content-Type:")) {
        body = line + "\r\n";
      } else if (isHeader) {
        headers += line + "\r\n";
      }
    }


    const cmsEnveloped = new pkijs.EnvelopedData();
    let cert = await getCertificate(certificate);
    cmsEnveloped.addRecipientByCertificate(cert, { oaepHashAlgorithm: "SHA-256" });
    const encAlg = {
      name: "AES-CBC",
      length: 128
    };
    await cmsEnveloped.encrypt(encAlg, pvutils.stringToArrayBuffer(body));
    const cmsContentSimpl = new pkijs.ContentInfo();
    cmsContentSimpl.contentType = "1.2.840.113549.1.7.3";
    cmsContentSimpl.content = cmsEnveloped.toSchema();
    const schema = cmsContentSimpl.toSchema();
    const ber = schema.toBER(false);
    setEncryptedEmail([
      headers + 'Content-Type: application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment; filename="smime.p7m"',
      'Content-Description: S/MIME Encrypted Message',
      "",
      btoa(String.fromCharCode(...new Uint8Array(ber))).match(/.{1,72}/g).join("\r\n"),
      '',
    ].join("\r\n"));

  }

  const decyptEmail = async () => {
    const certSimpl = await getCertificate(certificate);
    const privateKeyBuffer = await fromPEM(privateKey);
    const rawEmail = encryptedEmail.replace(/\n/g, "\r\n");

    const lines = rawEmail.split("\r\n");
    let isHeader = true;
    let headers = '';
    let body = '';
    for (const line of lines) {
      if (line.trim() === "\r\n" || line.trim() === "") {
        isHeader = false;
      } else if (isHeader && line.startsWith("Content-Type:")) {

      } else if (isHeader) {
        headers += line + "\r\n";
      } else {
        body += line + "\r\n";
      }
    }
    const parser = parse(rawEmail);
    const cmsContentSimpl = pkijs.ContentInfo.fromBER(parser.content.buffer);
    const cmsEnvelopedSimp = new pkijs.EnvelopedData({ schema: cmsContentSimpl.content });
    const decBody = await cmsEnvelopedSimp.decrypt(0,
      {
        recipientCertificate: certSimpl,
        recipientPrivateKey: privateKeyBuffer
      });

    setDecryptedEmail([
      headers,
      '',
      decBody
    ].join("\r\n"));
  };

  const fromPEM = async (pem) => {
    const base64 = pem
      .replace(/-{5}(BEGIN|END) .*-{5}/gm, "")
      .replace(/\s/gm, "");
    return pvtsutils.Convert.FromBase64(base64);
  };

  return (
    <div>
      <h1>Email Signer and Verifier</h1>
      <input type="file" onChange={handleFileUpload} />
      <br />
      <br />
      <text>Private Key</text>
      <br />
      <textarea
        value={privateKey}
        onChange={(e) => setPrivateKey(e.target.value)}
        placeholder="Enter Private Key content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <br />
      <text>Certificate</text>
      <br />
      <textarea
        value={certificate}
        onChange={(e) => setCertificate(e.target.value)}
        placeholder="Enter Certificate content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <br />
      <text>CA Certificate</text>
      <br />
      <textarea
        value={caCertificate}
        onChange={(e) => setCaCertificate(e.target.value)}
        placeholder="Enter CA Certificate content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <br />
      <text>Email</text>
      <br />
      <textarea
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter email content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <br />
      <text>Signed Email</text>
      <br />
      <textarea
        value={signedEmail}
        onChange={(e) => setSignedEmail(e.target.value)}
        placeholder="Enter signed email content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <br />
      <text>Encrypted Email</text>
      <br />
      <textarea
        value={encryptedEmail}
        onChange={(e) => setEncryptedEmail(e.target.value)}
        placeholder="Enter Enc content"
        style={{ width: '100%', height: '200px' }} // Set width and height here
      />
      <br />
      <button onClick={signEmail}> Sign</button>
      <br />
      <button onClick={verifyEmail}> Verify</button>
      <br />
      <button onClick={decyptEmail}> Decrypt</button>
      <br />
      <button onClick={all}>Sign Email And Verify and Encrypt</button>
      <br />
      <br />
      <text>Decrypted Email</text>
      <br />
      <textarea readOnly value={decryptedEmail} style={{ width: '100%', height: '200px' }} />
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default EmailSigner;