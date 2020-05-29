## PKCS #1: RSA Cryptography Specifications

v2.2: https://tools.ietf.org/html/rfc8017

https://www.openssl.org/docs/man1.1.1/man1/openssl-rsa.html

PEM label ```-----BEGIN RSA PRIVATE KEY-----```

```asn1
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```  

## PKCS #5: Password-Based Cryptography Specification

v2.1: https://tools.ietf.org/html/rfc8018

```asn1
AlgorithmIdentifier { ALGORITHM-IDENTIFIER:InfoObjectSet } ::=
 SEQUENCE {
   algorithm ALGORITHM-IDENTIFIER.&id({InfoObjectSet}),
   parameters ALGORITHM-IDENTIFIER.&Type({InfoObjectSet}
   {@algorithm}) OPTIONAL
}

PBKDF2Algorithms ALGORITHM-IDENTIFIER ::= {
  {PBKDF2-params IDENTIFIED BY id-PBKDF2},
  ...
}

id-PBKDF2 OBJECT IDENTIFIER ::= {pkcs-5 12}

PBKDF2-params ::= SEQUENCE {
   salt CHOICE {
     specified OCTET STRING,
     otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
   },
   iterationCount INTEGER (1..MAX),
   keyLength INTEGER (1..MAX) OPTIONAL,
   prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
   algid-hmacWithSHA1
}

PBKDF2-SaltSources ALGORITHM-IDENTIFIER ::= { ... }

PBKDF2-PRFs ALGORITHM-IDENTIFIER ::= {
 ...
 {NULL IDENTIFIED BY id-hmacWithSHA256},
 ...
}

PBES2Algorithms ALGORITHM-IDENTIFIER ::= {
  {PBES2-params IDENTIFIED BY id-PBES2},
  ...
}

id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}

PBES2-params ::= SEQUENCE {
  keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
  encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }

PBES2-KDFs ALGORITHM-IDENTIFIER ::=
  { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }

PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }

id-hmacWithSHA256 OBJECT IDENTIFIER ::= {digestAlgorithm 9}

aes OBJECT IDENTIFIER ::= { nistAlgorithms 1 }
aes128-CBC-PAD OBJECT IDENTIFIER ::= { aes 2 }
aes256-CBC-PAD OBJECT IDENTIFIER ::= { aes 42 }

B.2.  Encryption Schemes

   An example encryption scheme for PBES2 (Section 6.2) is AES-CBC-Pad.
   The schemes defined in PKCS #5 v2.0 [RFC2898], DES-CBC-Pad,
   DES-EDE3-CBC-Pad, RC2-CBC-Pad, and RC5-CBC-Pad, are still supported,
   but DES-CBC-Pad, DES-EDE3-CBC-Pad, RC2-CBC-Pad are now considered
   legacy and should only be used for backwards compatibility reasons.
```

## PKCS #7: Cryptographic Message Syntax

v1.5: https://tools.ietf.org/html/rfc2315

```asn1
EncryptedData ::= SEQUENCE {
 version Version,
 encryptedContentInfo EncryptedContentInfo }

EncryptedContentInfo ::= SEQUENCE {
 contentType ContentType,
 contentEncryptionAlgorithm
   ContentEncryptionAlgorithmIdentifier,
 encryptedContent
   [0] IMPLICIT EncryptedContent OPTIONAL }

EncryptedContent ::= OCTET STRING

ContentInfo ::= SEQUENCE {
 contentType ContentType,
 content
   [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }

ContentType ::= OBJECT IDENTIFIER

pkcs-7 OBJECT IDENTIFIER ::=
 { iso(1) member-body(2) US(840) rsadsi(113549)
     pkcs(1) 7 }

data OBJECT IDENTIFIER ::= { pkcs-7 1 }
signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }
envelopedData OBJECT IDENTIFIER ::= { pkcs-7 3 }
signedAndEnvelopedData OBJECT IDENTIFIER ::=
  { pkcs-7 4 }
digestedData OBJECT IDENTIFIER ::= { pkcs-7 5 }
encryptedData OBJECT IDENTIFIER ::= { pkcs-7 6 }
```

## PKCS #8: Private-Key Information Syntax Specification

Proposed: https://tools.ietf.org/html/rfc5958

v1.2: https://tools.ietf.org/html/rfc5208

https://en.wikipedia.org/wiki/PKCS_8

https://www.openssl.org/docs/man1.1.1/man1/openssl-pkcs8.html

PEM label ```-----BEGIN ENCRYPTED PRIVATE KEY-----```
or ```-----BEGIN PRIVATE KEY-----```

```asn1
AlgorithmIdentifier, ALGORITHM-IDENTIFIER
  FROM PKCS-5 {iso(1) member-body(2) us(840) rsadsi(113549)
  pkcs(1) pkcs-5(5) modules(16) pkcs-5(1)};
         
EncryptedPrivateKeyInfo ::= SEQUENCE {
  encryptionAlgorithm  EncryptionAlgorithmIdentifier,
  encryptedData        EncryptedData }

EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

EncryptedData ::= OCTET STRING
```

> encryptionAlgorithm identifies the algorithm under which the private-key information is encrypted.  Two examples are PKCS #5's pbeWithMD2AndDES-CBC and pbeWithMD5AndDES-CBC [PKCS#5].

> encryptedData is the result of encrypting the private-key information.

## PKCS #12

v1.1: https://tools.ietf.org/html/rfc7292

https://en.wikipedia.org/wiki/PKCS_12

```asn1
PFX ::= SEQUENCE {
   version     INTEGER {v3(3)}(v3,...),
   authSafe    ContentInfo,
   macData     MacData OPTIONAL
}

MacData ::= SEQUENCE {
   mac         DigestInfo,
   macSalt     OCTET STRING,
   iterations  INTEGER DEFAULT 1
   -- Note: The default is for historical reasons and its
   --       use is deprecated.
}

ContentInfo, DigestInfo
     FROM PKCS-7 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
                  pkcs-7(7) modules(0) pkcs-7(1)}

As mentioned, the contentType field of authSafe shall be of type data
or signedData.  The content field of the authSafe shall, either
directly (data case) or indirectly (signedData case), contain a BER-
encoded value of type AuthenticatedSafe.

AuthenticatedSafe ::= SEQUENCE OF ContentInfo
   -- Data if unencrypted
   -- EncryptedData if password-encrypted
   -- EnvelopedData if public key-encrypted

An AuthenticatedSafe contains a sequence of ContentInfo values.  The
content field of these ContentInfo values contains either plaintext,
encrypted, or enveloped data.  In the case of encrypted or enveloped
data, the plaintext of the data holds the BER-encoding of an instance
of SafeContents.  Section 5.1 of this document describes the
construction of values of type AuthenticatedSafe in more detail.

PrivateKeyInfo, EncryptedPrivateKeyInfo
  FROM PKCS-8 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
              pkcs-8(8) modules(1) pkcs-8(1)}

PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
```
